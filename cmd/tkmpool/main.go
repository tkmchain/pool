package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	PoolName               string  `json:"poolName"`
	ListenHTTP             string  `json:"listenHTTP"`
	ListenStratum          string  `json:"listenStratum"`
	NodeRPC                string  `json:"nodeRPC"`
	WorkMethod             string  `json:"workMethod"`
	PoolWallet             string  `json:"poolWallet"`
	PayoutStateFile        string  `json:"payoutStateFile"`
	BlockRewardAntd        float64 `json:"blockRewardAntd"`
	NetworkFeePercent      float64 `json:"networkFeePercent"`
	MinPayoutAntd          float64 `json:"minPayoutAntd"`
	PaymentMode            string  `json:"paymentMode"`
	AutoPay                bool    `json:"autoPay"`
	PaymentIntervalSeconds int     `json:"paymentIntervalSeconds"`
}

type PayoutState struct {
	Balances map[string]float64 `json:"balances"`
	Payments []Payment          `json:"payments"`
}

type Work struct {
	SealHash string `json:"sealHash"`
	SeedHash string `json:"seedHash"`
	Target   string `json:"target"`
	Height   uint64 `json:"height"`
}

type Miner struct {
	Wallet         string    `json:"wallet"`
	Worker         string    `json:"worker"`
	AcceptedShares uint64    `json:"acceptedShares"`
	RejectedShares uint64    `json:"rejectedShares"`
	LastSeen       time.Time `json:"lastSeen"`
}

type Payment struct {
	Wallet    string    `json:"wallet"`
	Amount    float64   `json:"amountAntd"`
	Status    string    `json:"status"`
	TxHash    string    `json:"txHash,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

type Pool struct {
	cfg      Config
	rpc      *RPCClient
	mu       sync.RWMutex
	work     Work
	miners   map[string]*Miner
	balances map[string]float64
	payments []Payment
	started  time.Time
	shares   atomic.Uint64
}

type RPCClient struct {
	endpoint string
	method   string
	client   *http.Client
	nextID   atomic.Uint64
}

func main() {
	configPath := flag.String("config", "config.example.json", "path to JSON config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	pool := NewPool(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go pool.pollWork(ctx)
	go pool.paymentLoop(ctx)
	go func() {
		if err := pool.serveStratum(ctx); err != nil {
			log.Printf("stratum stopped: %v", err)
			cancel()
		}
	}()

	log.Printf("%s dashboard listening on http://%s", cfg.PoolName, cfg.ListenHTTP)
	if err := pool.serveHTTP(ctx); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func loadConfig(path string) (Config, error) {
	cfg := Config{
		PoolName:               "TKM Pool",
		ListenHTTP:             "127.0.0.1:8080",
		ListenStratum:          "0.0.0.0:3333",
		NodeRPC:                "http://127.0.0.1:8545",
		WorkMethod:             "miner",
		PayoutStateFile:        "payout-state.json",
		BlockRewardAntd:        100,
		NetworkFeePercent:      1,
		MinPayoutAntd:          5,
		PaymentMode:            "PROP",
		PaymentIntervalSeconds: 300,
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if cfg.PaymentIntervalSeconds <= 0 {
		cfg.PaymentIntervalSeconds = 300
	}
	if cfg.WorkMethod == "" {
		cfg.WorkMethod = "miner"
	}
	if cfg.PayoutStateFile == "" {
		cfg.PayoutStateFile = "payout-state.json"
	}
	if cfg.BlockRewardAntd <= 0 {
		cfg.BlockRewardAntd = 100
	}
	cfg.PoolWallet = normalizeAddress(cfg.PoolWallet)
	return cfg, nil
}

func NewPool(cfg Config) *Pool {
	pool := &Pool{
		cfg:      cfg,
		rpc:      &RPCClient{endpoint: cfg.NodeRPC, method: strings.ToLower(cfg.WorkMethod), client: &http.Client{Timeout: 10 * time.Second}},
		miners:   make(map[string]*Miner),
		balances: make(map[string]float64),
		started:  time.Now(),
	}
	pool.loadPayoutState()
	return pool
}

func (p *Pool) loadPayoutState() {
	if p.cfg.PayoutStateFile == "" {
		return
	}
	b, err := os.ReadFile(p.cfg.PayoutStateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("payout state read failed: %v", err)
		}
		return
	}
	var state PayoutState
	if err := json.Unmarshal(b, &state); err != nil {
		log.Printf("payout state decode failed: %v", err)
		return
	}
	p.mu.Lock()
	if state.Balances != nil {
		balances := make(map[string]float64, len(state.Balances))
		for wallet, balance := range state.Balances {
			normalized := normalizeAddress(wallet)
			if !isValidAddress(normalized) {
				log.Printf("dropping invalid payout balance wallet=%s balance=%f", wallet, balance)
				continue
			}
			balances[normalized] += balance
		}
		p.balances = balances
	}
	p.payments = append([]Payment(nil), state.Payments...)
	for i := range p.payments {
		p.payments[i].Wallet = normalizeAddress(p.payments[i].Wallet)
	}
	p.savePayoutStateLocked()
	p.mu.Unlock()
}

func (p *Pool) savePayoutStateLocked() {
	if p.cfg.PayoutStateFile == "" {
		return
	}
	state := PayoutState{
		Balances: make(map[string]float64, len(p.balances)),
		Payments: append([]Payment(nil), p.payments...),
	}
	for wallet, balance := range p.balances {
		state.Balances[wallet] = round(balance)
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("payout state encode failed: %v", err)
		return
	}
	if err := os.WriteFile(p.cfg.PayoutStateFile, b, 0600); err != nil {
		log.Printf("payout state write failed: %v", err)
	}
}

func (p *Pool) pollWork(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		work, err := p.rpc.GetWork(ctx)
		if err != nil {
			log.Printf("work poll failed: %v", err)
		} else {
			p.mu.Lock()
			p.work = work
			p.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *Pool) serveStratum(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.cfg.ListenStratum)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("stratum listening on %s", p.cfg.ListenStratum)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go p.handleStratum(conn)
	}
}

type stratumRequest struct {
	ID     any             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func (p *Pool) handleStratum(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Minute))
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	sessionID := randomHex(8)
	wallet := ""
	worker := ""

	for {
		var req stratumRequest
		if err := dec.Decode(&req); err != nil {
			if err != io.EOF {
				log.Printf("stratum decode failed: %v", err)
			}
			return
		}

		switch req.Method {
		case "mining.subscribe":
			_ = enc.Encode(map[string]any{
				"id":     req.ID,
				"result": []any{[]any{[]any{"mining.notify", sessionID}}, sessionID, 4},
				"error":  nil,
			})
			p.notify(enc)
		case "mining.authorize":
			wallet, worker = parseAuthorize(req.Params)
			p.touchMiner(wallet, worker)
			_ = enc.Encode(map[string]any{"id": req.ID, "result": wallet != "", "error": nil})
		case "mining.submit":
			if wallet == "" {
				_ = enc.Encode(map[string]any{"id": req.ID, "result": false, "error": "unauthorized"})
				continue
			}
			ok := p.submitShare(context.Background(), wallet, worker, req.Params)
			_ = enc.Encode(map[string]any{"id": req.ID, "result": ok, "error": nil})
		case "mining.extranonce.subscribe":
			_ = enc.Encode(map[string]any{"id": req.ID, "result": true, "error": nil})
		default:
			_ = enc.Encode(map[string]any{"id": req.ID, "result": nil, "error": "unsupported method"})
		}
	}
}

func (p *Pool) notify(enc *json.Encoder) {
	p.mu.RLock()
	work := p.work
	p.mu.RUnlock()
	if work.SealHash == "" {
		return
	}
	_ = enc.Encode(map[string]any{
		"id":     nil,
		"method": "mining.notify",
		"params": []any{
			strconv.FormatUint(work.Height, 16),
			work.SealHash,
			work.SeedHash,
			work.Target,
			true,
		},
	})
}

func parseAuthorize(raw json.RawMessage) (string, string) {
	var params []string
	_ = json.Unmarshal(raw, &params)
	if len(params) == 0 {
		return "", ""
	}
	user := params[0]
	wallet, worker, _ := strings.Cut(user, ".")
	wallet = normalizeAddress(wallet)
	if !isValidAddress(wallet) {
		log.Printf("invalid miner payout wallet rejected wallet=%s", strings.TrimSpace(wallet))
		return "", strings.TrimSpace(worker)
	}
	return wallet, strings.TrimSpace(worker)
}

func (p *Pool) touchMiner(wallet, worker string) {
	if wallet == "" {
		return
	}
	key := wallet + "." + worker
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.miners[key]
	if m == nil {
		m = &Miner{Wallet: wallet, Worker: worker}
		p.miners[key] = m
	}
	m.LastSeen = time.Now()
}

func (p *Pool) submitShare(ctx context.Context, wallet, worker string, raw json.RawMessage) bool {
	var params []string
	_ = json.Unmarshal(raw, &params)
	p.mu.RLock()
	work := p.work
	p.mu.RUnlock()

	accepted := false
	if work.SealHash != "" && len(params) >= 4 {
		nonce := normalizeHex(params[2])
		digest := normalizeHex(params[3])
		if nonce != "" && digest != "" {
			if !digestMeetsTarget(digest, work.Target) {
				log.Printf("share below block target wallet=%s worker=%s nonce=%s", wallet, worker, nonce)
			} else {
				var err error
				accepted, err = p.rpc.SubmitWorkRaw(ctx, nonce, work.SealHash, digest)
				if err != nil {
					log.Printf("share submit failed wallet=%s worker=%s err=%v", wallet, worker, err)
				} else if !accepted {
					log.Printf("block candidate rejected by daemon wallet=%s worker=%s nonce=%s", wallet, worker, nonce)
				}
			}
		}
	}

	key := wallet + "." + worker
	p.mu.Lock()
	m := p.miners[key]
	if m == nil {
		m = &Miner{Wallet: wallet, Worker: worker}
		p.miners[key] = m
	}
	m.LastSeen = time.Now()
	if accepted {
		m.AcceptedShares++
		p.shares.Add(1)
	} else {
		m.RejectedShares++
	}
	p.mu.Unlock()

	if accepted {
		p.calculateRound(p.cfg.BlockRewardAntd)
		if p.cfg.AutoPay {
			go p.payDue(context.Background())
		}
	}
	return accepted
}

func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "0x") {
		return s
	}
	return "0x" + s
}

func normalizeAddress(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && strings.EqualFold(s[:2], "0x") {
		s = s[2:]
	}
	if len(s) == 40 && isHexString(s) {
		return "0x" + s
	}
	return strings.TrimSpace(s)
}

func isValidAddress(s string) bool {
	s = normalizeAddress(s)
	return len(s) == 42 && strings.HasPrefix(strings.ToLower(s), "0x") && isHexString(s[2:])
}

func isHexString(s string) bool {
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func (p *Pool) paymentLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(p.cfg.PaymentIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if p.cfg.AutoPay {
				p.payDue(ctx)
			}
		}
	}
}

func (p *Pool) calculateRound(blockRewardAntd float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := uint64(0)
	byWallet := map[string]uint64{}
	for _, m := range p.miners {
		total += m.AcceptedShares
		byWallet[m.Wallet] += m.AcceptedShares
		m.AcceptedShares = 0
		m.RejectedShares = 0
	}
	if total == 0 {
		return
	}
	netReward := blockRewardAntd * (1 - p.cfg.NetworkFeePercent/100)
	for wallet, shares := range byWallet {
		p.balances[wallet] += netReward * float64(shares) / float64(total)
	}
	p.savePayoutStateLocked()
}

func (p *Pool) payDue(ctx context.Context) {
	p.mu.RLock()
	var due []Payment
	for wallet, balance := range p.balances {
		if balance >= p.cfg.MinPayoutAntd {
			due = append(due, Payment{Wallet: wallet, Amount: round(balance), Status: "pending", CreatedAt: time.Now()})
		}
	}
	p.mu.RUnlock()

	for _, payment := range due {
		tx, err := p.rpc.SendPayment(ctx, p.cfg.PoolWallet, payment.Wallet, payment.Amount)
		p.mu.Lock()
		if err != nil {
			payment.Status = "failed: " + err.Error()
		} else {
			payment.Status = "sent"
			payment.TxHash = tx
			p.balances[payment.Wallet] = round(p.balances[payment.Wallet] - payment.Amount)
			if p.balances[payment.Wallet] <= 0 {
				delete(p.balances, payment.Wallet)
			}
		}
		p.payments = append(p.payments, payment)
		p.savePayoutStateLocked()
		p.mu.Unlock()
	}
}

func (p *Pool) serveHTTP(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(strings.ReplaceAll(indexHTML, "{{POOL_NAME}}", p.cfg.PoolName)))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		p.writeStatus(w)
	})
	mux.HandleFunc("/api/payments/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p.payDue(r.Context())
		p.writeStatus(w)
	})
	server := &http.Server{Addr: p.cfg.ListenHTTP, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	return server.ListenAndServe()
}

func (p *Pool) writeStatus(w http.ResponseWriter) {
	p.mu.RLock()
	miners := make([]Miner, 0, len(p.miners))
	for _, m := range p.miners {
		miners = append(miners, *m)
	}
	balances := make(map[string]float64, len(p.balances))
	for k, v := range p.balances {
		balances[k] = round(v)
	}
	payments := append([]Payment(nil), p.payments...)
	work := p.work
	p.mu.RUnlock()

	resp := map[string]any{
		"poolName":      p.cfg.PoolName,
		"paymentMode":   p.cfg.PaymentMode,
		"workMethod":    p.cfg.WorkMethod,
		"autoPay":       p.cfg.AutoPay,
		"minPayoutAntd": p.cfg.MinPayoutAntd,
		"feePercent":    p.cfg.NetworkFeePercent,
		"stratum":       p.cfg.ListenStratum,
		"nodeRPC":       p.cfg.NodeRPC,
		"poolWallet":    p.cfg.PoolWallet,
		"uptimeSeconds": int(time.Since(p.started).Seconds()),
		"totalShares":   p.shares.Load(),
		"work":          work,
		"miners":        miners,
		"balances":      balances,
		"payments":      payments,
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (r *RPCClient) call(ctx context.Context, method string, params any, result any) error {
	id := r.nextID.Add(1)
	reqBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("rpc status %s", resp.Status)
	}
	var decoded struct {
		Result json.RawMessage `json:"result"`
		Error  any             `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return err
	}
	if decoded.Error != nil {
		return fmt.Errorf("rpc error: %v", decoded.Error)
	}
	if result != nil {
		return json.Unmarshal(decoded.Result, result)
	}
	return nil
}

func (r *RPCClient) GetWork(ctx context.Context) (Work, error) {
	var tuple []string
	switch r.method {
	case "randomx":
		if err := r.call(ctx, "randomx_getWork", []any{}, &tuple); err != nil {
			return Work{}, err
		}
	case "auto":
		if err := r.call(ctx, "randomx_getWork", []any{}, &tuple); err != nil {
			if fallbackErr := r.call(ctx, "miner_getWork", []any{}, &tuple); fallbackErr != nil {
				return Work{}, fmt.Errorf("randomx_getWork failed: %w; miner_getWork failed: %v", err, fallbackErr)
			}
		}
	default:
		if err := r.call(ctx, "miner_getWork", []any{}, &tuple); err != nil {
			return Work{}, err
		}
	}
	if len(tuple) < 4 {
		return Work{}, fmt.Errorf("unexpected work tuple length %d", len(tuple))
	}
	height := parseUintFlexible(tuple[3])
	return Work{SealHash: tuple[0], SeedHash: tuple[1], Target: tuple[2], Height: height}, nil
}

func (r *RPCClient) SubmitWorkRaw(ctx context.Context, nonce, sealHash, digest string) (bool, error) {
	var accepted bool
	switch r.method {
	case "randomx":
		if err := r.call(ctx, "randomx_submitWorkRaw", []any{nonce, sealHash, digest}, &accepted); err != nil {
			return false, err
		}
	case "auto":
		if err := r.call(ctx, "miner_submitWork", []any{nonce, sealHash, digest}, &accepted); err != nil {
			if fallbackErr := r.call(ctx, "randomx_submitWorkRaw", []any{nonce, sealHash, digest}, &accepted); fallbackErr != nil {
				return false, fmt.Errorf("miner_submitWork failed: %w; randomx_submitWorkRaw failed: %v", err, fallbackErr)
			}
		}
	default:
		if err := r.call(ctx, "miner_submitWork", []any{nonce, sealHash, digest}, &accepted); err != nil {
			return false, err
		}
	}
	return accepted, nil
}

func (r *RPCClient) SendPayment(ctx context.Context, from, to string, amountAntd float64) (string, error) {
	from = normalizeAddress(from)
	to = normalizeAddress(to)
	if !isValidAddress(from) {
		return "", fmt.Errorf("invalid payout from address %q", from)
	}
	if !isValidAddress(to) {
		return "", fmt.Errorf("invalid payout to address %q", to)
	}
	valueWei := antdToWeiHex(amountAntd)
	var tx string
	err := r.call(ctx, "eth_sendTransaction", []any{map[string]any{"from": from, "to": to, "value": valueWei}}, &tx)
	return tx, err
}

func antdToWeiHex(amount float64) string {
	wei := new(big.Float).Mul(big.NewFloat(amount), big.NewFloat(1e18))
	i, _ := wei.Int(nil)
	return "0x" + i.Text(16)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func digestMeetsTarget(digestHex, targetHex string) bool {
	digest, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimSpace(digestHex), "0x"), 16)
	if !ok {
		return false
	}
	target, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimSpace(targetHex), "0x"), 16)
	if !ok {
		return false
	}
	return digest.Cmp(target) <= 0
}

func parseUintFlexible(s string) uint64 {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") {
		v, _ := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func round(v float64) float64 {
	return math.Round(v*1e8) / 1e8
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{POOL_NAME}}</title>
  <style>
    :root { color-scheme: light; --bg:#f7f8fb; --ink:#141821; --muted:#5b6472; --line:#d9dee7; --panel:#ffffff; --green:#12805c; --red:#b42318; --blue:#1b5fc1; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; }
    header { background:#111827; color:white; padding:22px 28px; display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; }
    h1 { margin:0; font-size:24px; letter-spacing:0; }
    main { max-width:1180px; margin:0 auto; padding:24px; }
    .grid { display:grid; gap:14px; grid-template-columns:repeat(4, minmax(0, 1fr)); }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    .metric { min-height:104px; }
    .label { color:var(--muted); font-size:12px; text-transform:uppercase; font-weight:700; }
    .value { font-size:24px; font-weight:750; margin-top:8px; overflow-wrap:anywhere; }
    .section { margin-top:18px; }
    .section h2 { font-size:17px; margin:0 0 12px; }
    table { width:100%; border-collapse:collapse; }
    th, td { padding:10px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; }
    code { background:#eef2f7; border:1px solid var(--line); border-radius:5px; padding:2px 5px; }
    button { border:1px solid #0f4ea8; background:var(--blue); color:white; border-radius:6px; padding:9px 12px; font-weight:700; cursor:pointer; }
    button:disabled { opacity:.55; cursor:wait; }
    .ok { color:var(--green); font-weight:700; }
    .bad { color:var(--red); font-weight:700; }
    .muted { color:var(--muted); }
    .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    @media (max-width: 860px) { .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } main { padding:16px; } }
    @media (max-width: 560px) { .grid { grid-template-columns:1fr; } header { padding:18px; } .value { font-size:20px; } }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{{POOL_NAME}}</h1>
      <div class="muted">RandomX Tkmchain mining pool</div>
    </div>
    <div class="row">
      <span>Stratum <code id="stratum">loading</code></span>
      <button id="refresh">Refresh</button>
    </div>
  </header>
  <main>
    <div class="grid">
      <div class="panel metric"><div class="label">Pool Shares</div><div class="value" id="shares">0</div></div>
      <div class="panel metric"><div class="label">Connected Workers</div><div class="value" id="workers">0</div></div>
      <div class="panel metric"><div class="label">Current Height</div><div class="value" id="height">0</div></div>
      <div class="panel metric"><div class="label">Payment Method</div><div class="value" id="payment">PROP</div></div>
    </div>

    <section class="section panel">
      <h2>Connection</h2>
      <table>
        <tbody>
          <tr><th>Miner URL</th><td><code id="minerUrl"></code></td></tr>
          <tr><th>Username</th><td>Your TKM payout wallet, optionally <code>0xWallet.worker</code></td></tr>
          <tr><th>Password</th><td><code>x</code></td></tr>
          <tr><th>Pool Wallet</th><td id="poolWallet"></td></tr>
        </tbody>
      </table>
    </section>

    <section class="section panel">
      <div class="row" style="justify-content:space-between">
        <h2>Payments</h2>
        <button id="runPayments">Run Accounting</button>
      </div>
      <table>
        <tbody>
          <tr><th>Mode</th><td id="payMode"></td></tr>
          <tr><th>Minimum Payout</th><td id="minPayout"></td></tr>
          <tr><th>Pool Fee</th><td id="fee"></td></tr>
          <tr><th>Auto Pay</th><td id="autoPay"></td></tr>
        </tbody>
      </table>
      <h2 style="margin-top:18px">Balances</h2>
      <table><thead><tr><th>Wallet</th><th>Balance ANTD</th></tr></thead><tbody id="balances"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Workers</h2>
      <table><thead><tr><th>Wallet</th><th>Worker</th><th>Accepted</th><th>Rejected</th><th>Last Seen</th></tr></thead><tbody id="miners"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Recent Payouts</h2>
      <table><thead><tr><th>Wallet</th><th>Amount</th><th>Status</th><th>Transaction</th></tr></thead><tbody id="payments"></tbody></table>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    function row(cells) { return '<tr>' + cells.map(v => '<td>' + String(v ?? '') + '</td>').join('') + '</tr>'; }
    async function load() {
      const res = await fetch('/api/status');
      const s = await res.json();
      $('shares').textContent = s.totalShares;
      $('workers').textContent = s.miners.length;
      $('height').textContent = s.work.height || 0;
      $('payment').textContent = s.paymentMode;
      $('stratum').textContent = s.stratum;
      $('minerUrl').textContent = 'stratum+tcp://' + s.stratum;
      $('poolWallet').textContent = s.poolWallet;
      $('payMode').textContent = s.paymentMode + ' proportional accepted-share accounting';
      $('minPayout').textContent = s.minPayoutAntd + ' ANTD';
      $('fee').textContent = s.feePercent + '%';
      $('autoPay').innerHTML = s.autoPay ? '<span class="ok">enabled</span>' : '<span class="bad">disabled</span>';
      $('miners').innerHTML = s.miners.map(m => row([m.wallet, m.worker || '-', m.acceptedShares, m.rejectedShares, new Date(m.lastSeen).toLocaleString()])).join('') || row(['No workers connected', '', '', '', '']);
      $('balances').innerHTML = Object.entries(s.balances).map(([w,b]) => row([w, b])).join('') || row(['No balances yet', '0']);
      $('payments').innerHTML = s.payments.map(p => row([p.wallet, p.amountAntd, p.status, p.txHash || '-'])).join('') || row(['No payouts yet', '', '', '']);
    }
    $('refresh').onclick = load;
    $('runPayments').onclick = async () => {
      $('runPayments').disabled = true;
      await fetch('/api/payments/run', { method: 'POST' });
      $('runPayments').disabled = false;
      load();
    };
    load();
    setInterval(load, 15000);
  </script>
</body>
</html>`

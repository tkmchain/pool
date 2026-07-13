package main

import (
	"bufio"
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
	PoolWalletPassword     string  `json:"poolWalletPassword"`
	RedisAddr              string  `json:"redisAddr"`
	RedisPassword          string  `json:"redisPassword"`
	RedisDB                int     `json:"redisDB"`
	RedisStateKey          string  `json:"redisStateKey"`
	BlockRewardAntd        float64 `json:"blockRewardAntd"`
	NetworkFeePercent      float64 `json:"networkFeePercent"`
	MinPayoutAntd          float64 `json:"minPayoutAntd"`
	MaxPayoutPerTxAntd     float64 `json:"maxPayoutPerTxAntd"`
	PaymentMode            string  `json:"paymentMode"`
	AutoPay                bool    `json:"autoPay"`
	PaymentIntervalSeconds int     `json:"paymentIntervalSeconds"`
	PaymentConfirmations   int     `json:"paymentConfirmations"`
	PayoutReserveAntd      float64 `json:"payoutReserveAntd"`
	RPCTimeoutSeconds      int     `json:"rpcTimeoutSeconds"`
	ShareTarget            string  `json:"shareTarget"`
}

type PayoutState struct {
	Balances    map[string]float64 `json:"balances"`
	Payments    []Payment          `json:"payments"`
	Miners      map[string]Miner   `json:"miners"`
	TotalShares uint64             `json:"totalShares"`
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
	RoundShares    uint64    `json:"roundShares"`
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
	jobs     map[string]Work
	sessions map[*stratumSession]struct{}
	logMu    sync.Mutex
	lastLog  map[string]logThrottle
	started  time.Time
	shares   atomic.Uint64
	paying   atomic.Bool
}

type logThrottle struct {
	last       time.Time
	suppressed int
}

type stratumSession struct {
	enc *json.Encoder
	mu  sync.Mutex
}

func (s *stratumSession) write(v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(v)
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

	pool.ensurePoolWalletEtherbase(ctx)

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
		RedisStateKey:          "tkmpool:payout-state",
		BlockRewardAntd:        100,
		NetworkFeePercent:      1,
		MinPayoutAntd:          5,
		MaxPayoutPerTxAntd:     25,
		PaymentMode:            "PROP",
		PaymentIntervalSeconds: 300,
		PaymentConfirmations:   12,
		PayoutReserveAntd:      0.1,
		RPCTimeoutSeconds:      60,
		ShareTarget:            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
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
	if cfg.MaxPayoutPerTxAntd <= 0 {
		cfg.MaxPayoutPerTxAntd = cfg.MinPayoutAntd
	}
	if cfg.PaymentConfirmations < 0 {
		cfg.PaymentConfirmations = 0
	}
	if cfg.RPCTimeoutSeconds <= 0 {
		cfg.RPCTimeoutSeconds = 60
	}
	if cfg.WorkMethod == "" {
		cfg.WorkMethod = "miner"
	}
	if cfg.ShareTarget == "" {
		cfg.ShareTarget = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	cfg.ShareTarget = normalizeHex(cfg.ShareTarget)
	if cfg.RedisStateKey == "" {
		cfg.RedisStateKey = "tkmpool:payout-state"
	}
	if cfg.BlockRewardAntd <= 0 {
		cfg.BlockRewardAntd = 100
	}
	cfg.PoolWallet = normalizeAddress(cfg.PoolWallet)
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = "127.0.0.1:6379"
	}
	return cfg, nil
}

func NewPool(cfg Config) *Pool {
	pool := &Pool{
		cfg:      cfg,
		rpc:      &RPCClient{endpoint: cfg.NodeRPC, method: strings.ToLower(cfg.WorkMethod), client: &http.Client{Timeout: time.Duration(cfg.RPCTimeoutSeconds) * time.Second}},
		miners:   make(map[string]*Miner),
		balances: make(map[string]float64),
		jobs:     make(map[string]Work),
		sessions: make(map[*stratumSession]struct{}),
		lastLog:  make(map[string]logThrottle),
		started:  time.Now(),
	}
	pool.loadPayoutState()
	return pool
}

func (p *Pool) ensurePoolWalletEtherbase(ctx context.Context) {
	if !isValidAddress(p.cfg.PoolWallet) {
		log.Printf("pool wallet is not a valid etherbase address wallet=%s", p.cfg.PoolWallet)
		return
	}
	timeout := 10 * time.Second
	if p.cfg.RPCTimeoutSeconds > 0 && p.cfg.RPCTimeoutSeconds < 10 {
		timeout = time.Duration(p.cfg.RPCTimeoutSeconds) * time.Second
	}
	setCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	coinbase, err := p.rpc.Coinbase(setCtx)
	if err == nil && strings.EqualFold(normalizeAddress(coinbase), p.cfg.PoolWallet) {
		log.Printf("daemon etherbase already matches pool wallet wallet=%s", p.cfg.PoolWallet)
		return
	}
	if err != nil {
		log.Printf("daemon coinbase check failed before setting pool wallet etherbase: %v", err)
	}
	ok, err := p.rpc.SetEtherbase(setCtx, p.cfg.PoolWallet)
	if err != nil || !ok {
		log.Printf("pool wallet is not configured as daemon etherbase; start gtkm with --miner.etherbase %s or enable miner RPC API for miner_setEtherbase: %v", p.cfg.PoolWallet, err)
		return
	}
	log.Printf("updated daemon etherbase to pool wallet wallet=%s previous=%s", p.cfg.PoolWallet, coinbase)
}

func (p *Pool) loadPayoutState() {
	state, ok, err := p.readRedisPayoutState()
	if err != nil {
		log.Fatalf("redis payout state read failed: %v", err)
	}
	p.mu.Lock()
	if ok {
		p.applyPayoutStateLocked(state)
	}
	p.savePayoutStateLocked()
	p.mu.Unlock()
}

func (p *Pool) applyPayoutStateLocked(state PayoutState) {
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
	p.payments = append([]Payment{}, state.Payments...)
	for i := range p.payments {
		p.payments[i].Wallet = normalizeAddress(p.payments[i].Wallet)
	}
	if state.Miners != nil {
		p.miners = make(map[string]*Miner, len(state.Miners))
		for key, miner := range state.Miners {
			miner.Wallet = normalizeAddress(miner.Wallet)
			if !isValidAddress(miner.Wallet) {
				log.Printf("dropping invalid miner wallet=%s", miner.Wallet)
				continue
			}
			if key == "" {
				key = minerKey(miner.Wallet, miner.Worker)
			}
			m := miner
			p.miners[key] = &m
		}
	}
	if state.TotalShares > 0 {
		p.shares.Store(state.TotalShares)
	}
}

func (p *Pool) readRedisPayoutState() (PayoutState, bool, error) {
	b, err := p.redisCommand("GET", p.cfg.RedisStateKey)
	if err != nil {
		return PayoutState{}, false, err
	}
	if b == nil {
		return PayoutState{}, false, nil
	}
	var state PayoutState
	if err := json.Unmarshal(b, &state); err != nil {
		return PayoutState{}, false, err
	}
	return state, true, nil
}

func (p *Pool) savePayoutStateLocked() {
	state := PayoutState{
		Balances:    make(map[string]float64, len(p.balances)),
		Payments:    append([]Payment{}, p.payments...),
		Miners:      make(map[string]Miner, len(p.miners)),
		TotalShares: p.shares.Load(),
	}
	for wallet, balance := range p.balances {
		state.Balances[wallet] = round(balance)
	}
	for key, miner := range p.miners {
		if miner != nil {
			state.Miners[key] = *miner
		}
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("payout state encode failed: %v", err)
		return
	}
	if _, err := p.redisCommand("SET", p.cfg.RedisStateKey, string(b)); err != nil {
		log.Fatalf("redis payout state write failed: %v", err)
	}
}

func (p *Pool) redisCommand(command string, args ...string) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", p.cfg.RedisAddr, time.Duration(p.cfg.RPCTimeoutSeconds)*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(p.cfg.RPCTimeoutSeconds) * time.Second))
	reader := bufio.NewReader(conn)
	if p.cfg.RedisPassword != "" {
		if _, err := redisWriteRead(conn, reader, "AUTH", p.cfg.RedisPassword); err != nil {
			return nil, err
		}
	}
	if p.cfg.RedisDB > 0 {
		if _, err := redisWriteRead(conn, reader, "SELECT", strconv.Itoa(p.cfg.RedisDB)); err != nil {
			return nil, err
		}
	}
	return redisWriteRead(conn, reader, append([]string{command}, args...)...)
}

func redisWriteRead(conn net.Conn, reader *bufio.Reader, parts ...string) ([]byte, error) {
	if _, err := fmt.Fprintf(conn, "*%d\r\n", len(parts)); err != nil {
		return nil, err
	}
	for _, part := range parts {
		if _, err := fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(part), part); err != nil {
			return nil, err
		}
	}
	return redisReadRESP(reader)
}

func redisReadRESP(reader *bufio.Reader) ([]byte, error) {
	prefix, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	switch prefix {
	case '+':
		return []byte(line), nil
	case '-':
		return nil, fmt.Errorf("redis error: %s", line)
	case ':':
		return []byte(line), nil
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(reader, b); err != nil {
			return nil, err
		}
		return b[:n], nil
	default:
		return nil, fmt.Errorf("unsupported redis response prefix %q", prefix)
	}
}

func (p *Pool) pollWork(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		work, err := p.rpc.GetWork(ctx)
		if err != nil {
			log.Printf("work poll failed: %v", err)
		} else if work.SealHash != "" {
			var sessions []*stratumSession
			p.mu.Lock()
			changed := p.work.SealHash != work.SealHash
			p.work = work
			if changed {
				p.jobs = map[string]Work{jobID(work): work}
			} else {
				p.jobs[jobID(work)] = work
			}
			if changed {
				for session := range p.sessions {
					sessions = append(sessions, session)
				}
			}
			p.mu.Unlock()
			if changed {
				log.Printf("new work height=%d job=%s target=%s miners=%d", work.Height, shortID(jobID(work)), shortID(work.Target), len(sessions))
			}
			for _, session := range sessions {
				p.notify(session, work)
			}
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
	session := &stratumSession{enc: enc}
	p.mu.Lock()
	p.sessions[session] = struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.sessions, session)
		p.mu.Unlock()
	}()

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
			session.write(map[string]any{
				"id":     req.ID,
				"result": []any{[]any{[]any{"mining.notify", sessionID}}, sessionID, 4},
				"error":  nil,
			})
			p.notifyCurrent(session)
		case "mining.authorize":
			wallet, worker = parseAuthorize(req.Params)
			p.touchMiner(wallet, worker)
			session.write(map[string]any{"id": req.ID, "result": wallet != "", "error": nil})
		case "mining.submit":
			if wallet == "" {
				session.write(map[string]any{"id": req.ID, "result": false, "error": "unauthorized"})
				continue
			}
			ok := p.submitShare(context.Background(), wallet, worker, req.Params)
			session.write(map[string]any{"id": req.ID, "result": ok, "error": nil})
		case "mining.extranonce.subscribe":
			session.write(map[string]any{"id": req.ID, "result": true, "error": nil})
		default:
			session.write(map[string]any{"id": req.ID, "result": nil, "error": "unsupported method"})
		}
	}
}

func (p *Pool) notifyCurrent(session *stratumSession) {
	p.mu.RLock()
	work := p.work
	p.mu.RUnlock()
	p.notify(session, work)
}

func (p *Pool) notify(session *stratumSession, work Work) {
	if work.SealHash == "" {
		return
	}
	session.write(map[string]any{
		"id":     nil,
		"method": "mining.notify",
		"params": []any{
			jobID(work),
			work.SealHash,
			work.SeedHash,
			p.cfg.ShareTarget,
			true,
		},
	})
}

func jobID(work Work) string {
	return work.SealHash
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

func minerKey(wallet, worker string) string {
	return wallet + "." + worker
}

func (p *Pool) touchMiner(wallet, worker string) {
	if wallet == "" {
		return
	}
	key := minerKey(wallet, worker)
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.miners[key]
	if m == nil {
		m = &Miner{Wallet: wallet, Worker: worker}
		p.miners[key] = m
	}
	m.LastSeen = time.Now()
	p.savePayoutStateLocked()
}

func (p *Pool) recordRejectedShare(wallet, worker string) {
	key := minerKey(wallet, worker)
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.miners[key]
	if m == nil {
		m = &Miner{Wallet: wallet, Worker: worker}
		p.miners[key] = m
	}
	m.LastSeen = time.Now()
	m.RejectedShares++
	p.savePayoutStateLocked()
}

func shortID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 18 {
		return value
	}
	if strings.HasPrefix(value, "0x") && len(value) > 18 {
		return value[:10] + ".." + value[len(value)-6:]
	}
	return value[:8] + ".." + value[len(value)-6:]
}

func shortWallet(wallet string) string {
	wallet = normalizeAddress(wallet)
	if len(wallet) == 42 {
		return wallet[:8] + ".." + wallet[len(wallet)-4:]
	}
	return shortID(wallet)
}

func minerLabel(wallet, worker string) string {
	if worker == "" {
		return shortWallet(wallet)
	}
	return shortWallet(wallet) + "." + worker
}

func (p *Pool) logEvery(key string, interval time.Duration, format string, args ...any) {
	now := time.Now()
	p.logMu.Lock()
	entry := p.lastLog[key]
	if !entry.last.IsZero() && now.Sub(entry.last) < interval {
		entry.suppressed++
		p.lastLog[key] = entry
		p.logMu.Unlock()
		return
	}
	suppressed := entry.suppressed
	p.lastLog[key] = logThrottle{last: now}
	p.logMu.Unlock()

	if suppressed > 0 {
		format += " repeated=%d"
		args = append(args, suppressed)
	}
	log.Printf(format, args...)
}

func (p *Pool) submitShare(ctx context.Context, wallet, worker string, raw json.RawMessage) bool {
	var params []string
	_ = json.Unmarshal(raw, &params)
	p.mu.RLock()
	work := p.work
	currentJob := jobID(work)
	staleJob := len(params) < 2 || params[1] == "" || params[1] != currentJob
	p.mu.RUnlock()
	if staleJob {
		job := ""
		if len(params) >= 2 {
			job = params[1]
		}
		p.logEvery("stale:"+minerKey(wallet, worker)+":"+job, 10*time.Second, "share stale miner=%s job=%s current=%s", minerLabel(wallet, worker), shortID(job), shortID(currentJob))
		p.recordRejectedShare(wallet, worker)
		return false
	}

	shareAccepted := false
	blockAccepted := false
	if work.SealHash != "" && len(params) >= 4 {
		nonce := normalizeHex(params[2])
		digest := normalizeHex(params[3])
		if nonce != "" && digest != "" {
			if digestMeetsTarget(digest, p.cfg.ShareTarget) {
				shareAccepted = true
			} else {
				p.logEvery("lowdiff:"+minerKey(wallet, worker), 10*time.Second, "share low-diff miner=%s nonce=%s", minerLabel(wallet, worker), shortID(nonce))
			}
			if shareAccepted && digestMeetsTarget(digest, work.Target) {
				var err error
				blockAccepted, err = p.rpc.SubmitWorkRaw(ctx, nonce, work.SealHash, digest)
				if err != nil {
					log.Printf("block submit failed miner=%s err=%v", minerLabel(wallet, worker), err)
				} else if !blockAccepted {
					p.logEvery("blockreject:"+minerKey(wallet, worker), 10*time.Second, "block rejected miner=%s nonce=%s", minerLabel(wallet, worker), shortID(nonce))
				}
			}
		}
	}

	key := minerKey(wallet, worker)
	p.mu.Lock()
	m := p.miners[key]
	if m == nil {
		m = &Miner{Wallet: wallet, Worker: worker}
		p.miners[key] = m
	}
	m.LastSeen = time.Now()
	if shareAccepted {
		m.AcceptedShares++
		m.RoundShares++
		p.shares.Add(1)
	} else {
		m.RejectedShares++
	}
	p.savePayoutStateLocked()
	p.mu.Unlock()

	if blockAccepted {
		p.calculateRound(p.cfg.BlockRewardAntd)
		if p.cfg.AutoPay {
			go p.payDueWithConfirmations(context.Background(), 0)
		}
	}
	return shareAccepted
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
		total += m.RoundShares
		byWallet[m.Wallet] += m.RoundShares
		m.RoundShares = 0
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

func (p *Pool) pendingBalancesLocked() map[string]float64 {
	total := uint64(0)
	byWallet := map[string]uint64{}
	for _, m := range p.miners {
		total += m.RoundShares
		byWallet[m.Wallet] += m.RoundShares
	}
	pending := make(map[string]float64, len(byWallet))
	if total == 0 {
		return pending
	}
	netReward := p.cfg.BlockRewardAntd * (1 - p.cfg.NetworkFeePercent/100)
	for wallet, shares := range byWallet {
		pending[wallet] = round(netReward * float64(shares) / float64(total))
	}
	return pending
}

func (p *Pool) recordPaymentStatuses(payments []Payment, status string) {
	if len(payments) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, payment := range payments {
		payment.Status = status
		payment.TxHash = ""
		payment.CreatedAt = time.Now()
		p.payments = append(p.payments, payment)
	}
	p.savePayoutStateLocked()
}

func (p *Pool) payDue(ctx context.Context) {
	p.payDueWithConfirmations(ctx, p.cfg.PaymentConfirmations)
}

func (p *Pool) payDueWithConfirmations(ctx context.Context, confirmations int) {
	if !p.paying.CompareAndSwap(false, true) {
		return
	}
	defer p.paying.Store(false)

	p.mu.RLock()
	var due []Payment
	for wallet, balance := range p.balances {
		if balance >= p.cfg.MinPayoutAntd {
			due = append(due, Payment{Wallet: wallet, Amount: round(minFloat(balance, p.cfg.MaxPayoutPerTxAntd)), Status: "pending", CreatedAt: time.Now()})
		}
	}
	p.mu.RUnlock()
	if len(due) == 0 {
		return
	}

	confirmedBalance, blockNumber, err := p.rpc.ConfirmedBalance(ctx, p.cfg.PoolWallet, confirmations)
	if err != nil {
		log.Printf("autopay skipped: confirmed pool balance check failed: %v", err)
		p.recordPaymentStatuses(due, "waiting: confirmed pool balance check failed: "+err.Error())
		return
	}
	spendable := new(big.Int).Sub(confirmedBalance, antdToWeiInt(p.cfg.PayoutReserveAntd))
	if spendable.Sign() <= 0 {
		log.Printf("autopay skipped: confirmed pool balance is below reserve block=%d balanceWei=%s reserveAntd=%f", blockNumber, confirmedBalance.String(), p.cfg.PayoutReserveAntd)
		p.recordPaymentStatuses(due, fmt.Sprintf("waiting: confirmed pool balance below reserve at block %d", blockNumber))
		return
	}

	for _, payment := range due {
		amountWei := antdToWeiInt(payment.Amount)
		if amountWei.Cmp(spendable) > 0 {
			spendableAntd := weiToAntd(spendable)
			if spendableAntd >= p.cfg.MinPayoutAntd {
				payment.Amount = round(minFloat(spendableAntd, p.cfg.MaxPayoutPerTxAntd))
				amountWei = antdToWeiInt(payment.Amount)
			} else {
				log.Printf("autopay waiting for confirmed pool balance wallet=%s amountAntd=%f block=%d spendableWei=%s", payment.Wallet, payment.Amount, blockNumber, spendable.String())
				p.recordPaymentStatuses([]Payment{payment}, fmt.Sprintf("waiting: insufficient confirmed pool balance at block %d", blockNumber))
				continue
			}
		}
		tx, err := p.rpc.SendPayment(ctx, p.cfg.PoolWallet, payment.Wallet, payment.Amount, p.cfg.PoolWalletPassword)
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
			spendable.Sub(spendable, amountWei)
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
	mux.HandleFunc("/admin.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(strings.ReplaceAll(adminHTML, "{{POOL_NAME}}", p.cfg.PoolName)))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		p.writeStatus(w)
	})
	mux.HandleFunc("/api/admin/status", func(w http.ResponseWriter, r *http.Request) {
		p.writeAdminStatus(w, r)
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
	pendingBalances := p.pendingBalancesLocked()
	payments := append([]Payment{}, p.payments...)
	work := p.work
	p.mu.RUnlock()

	resp := map[string]any{
		"poolName":        p.cfg.PoolName,
		"paymentMode":     p.cfg.PaymentMode,
		"workMethod":      p.cfg.WorkMethod,
		"autoPay":         p.cfg.AutoPay,
		"minPayoutAntd":   p.cfg.MinPayoutAntd,
		"feePercent":      p.cfg.NetworkFeePercent,
		"stratum":         p.cfg.ListenStratum,
		"nodeRPC":         p.cfg.NodeRPC,
		"poolWallet":      p.cfg.PoolWallet,
		"uptimeSeconds":   int(time.Since(p.started).Seconds()),
		"totalShares":     p.shares.Load(),
		"work":            work,
		"miners":          miners,
		"balances":        balances,
		"pendingBalances": pendingBalances,
		"payments":        payments,
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *Pool) writeAdminStatus(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	miners := make([]Miner, 0, len(p.miners))
	for _, m := range p.miners {
		miners = append(miners, *m)
	}
	balances := make(map[string]float64, len(p.balances))
	for k, v := range p.balances {
		balances[k] = round(v)
	}
	pendingBalances := p.pendingBalancesLocked()
	payments := append([]Payment{}, p.payments...)
	work := p.work
	totalShares := p.shares.Load()
	p.mu.RUnlock()

	daemonCoinbase := ""
	daemonCoinbaseError := ""
	if coinbase, err := p.rpc.Coinbase(r.Context()); err != nil {
		daemonCoinbaseError = err.Error()
	} else {
		daemonCoinbase = normalizeAddress(coinbase)
	}

	poolWalletBalance := map[string]any{}
	if latestWei, latestBlock, err := p.rpc.ConfirmedBalance(r.Context(), p.cfg.PoolWallet, 0); err != nil {
		poolWalletBalance["latestError"] = err.Error()
	} else {
		poolWalletBalance["latestAntd"] = weiToAntd(latestWei)
		poolWalletBalance["latestBlock"] = latestBlock
	}
	if confirmedWei, confirmedBlock, err := p.rpc.ConfirmedBalance(r.Context(), p.cfg.PoolWallet, p.cfg.PaymentConfirmations); err != nil {
		poolWalletBalance["confirmedError"] = err.Error()
		poolWalletBalance["confirmedBlock"] = confirmedBlock
	} else {
		confirmedAntd := weiToAntd(confirmedWei)
		spendableAntd := round(confirmedAntd - p.cfg.PayoutReserveAntd)
		if spendableAntd < 0 {
			spendableAntd = 0
		}
		poolWalletBalance["confirmedAntd"] = confirmedAntd
		poolWalletBalance["confirmedBlock"] = confirmedBlock
		poolWalletBalance["spendableAntd"] = spendableAntd
	}

	redisInfo := map[string]any{
		"addr":     p.cfg.RedisAddr,
		"db":       p.cfg.RedisDB,
		"stateKey": p.cfg.RedisStateKey,
	}
	if raw, err := p.redisCommand("GET", p.cfg.RedisStateKey); err != nil {
		redisInfo["ok"] = false
		redisInfo["error"] = err.Error()
	} else {
		redisInfo["ok"] = true
		redisInfo["stateBytes"] = len(raw)
	}

	resp := map[string]any{
		"poolName":                       p.cfg.PoolName,
		"paymentMode":                    p.cfg.PaymentMode,
		"workMethod":                     p.cfg.WorkMethod,
		"autoPay":                        p.cfg.AutoPay,
		"minPayoutAntd":                  p.cfg.MinPayoutAntd,
		"maxPayoutPerTxAntd":             p.cfg.MaxPayoutPerTxAntd,
		"paymentIntervalSeconds":         p.cfg.PaymentIntervalSeconds,
		"paymentConfirmations":           p.cfg.PaymentConfirmations,
		"payoutReserveAntd":              p.cfg.PayoutReserveAntd,
		"blockRewardAntd":                p.cfg.BlockRewardAntd,
		"feePercent":                     p.cfg.NetworkFeePercent,
		"stratum":                        p.cfg.ListenStratum,
		"http":                           p.cfg.ListenHTTP,
		"nodeRPC":                        p.cfg.NodeRPC,
		"poolWallet":                     p.cfg.PoolWallet,
		"poolWalletPasswordConfigured":   p.cfg.PoolWalletPassword != "",
		"daemonCoinbase":                 daemonCoinbase,
		"daemonCoinbaseError":            daemonCoinbaseError,
		"poolWalletIsDaemonCoinbase":     daemonCoinbase != "" && strings.EqualFold(daemonCoinbase, p.cfg.PoolWallet),
		"uptimeSeconds":                  int(time.Since(p.started).Seconds()),
		"totalShares":                    totalShares,
		"workerCount":                    len(miners),
		"balanceCount":                   len(balances),
		"paymentCount":                   len(payments),
		"totalConfirmedMinerBalanceAntd": sumFloatMap(balances),
		"totalPendingRoundAntd":          sumFloatMap(pendingBalances),
		"poolWalletBalance":              poolWalletBalance,
		"redis":                          redisInfo,
		"work":                           work,
		"miners":                         miners,
		"balances":                       balances,
		"pendingBalances":                pendingBalances,
		"payments":                       payments,
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func sumFloatMap(values map[string]float64) float64 {
	var total float64
	for _, value := range values {
		total += value
	}
	return round(total)
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

func (r *RPCClient) BlockNumber(ctx context.Context) (uint64, error) {
	var blockHex string
	if err := r.call(ctx, "eth_blockNumber", []any{}, &blockHex); err != nil {
		return 0, err
	}
	return parseUintFlexible(blockHex), nil
}

func (r *RPCClient) Coinbase(ctx context.Context) (string, error) {
	var coinbase string
	if err := r.call(ctx, "eth_coinbase", []any{}, &coinbase); err != nil {
		return "", err
	}
	return normalizeAddress(coinbase), nil
}

func (r *RPCClient) SetEtherbase(ctx context.Context, address string) (bool, error) {
	address = normalizeAddress(address)
	if !isValidAddress(address) {
		return false, fmt.Errorf("invalid etherbase address %q", address)
	}
	var ok bool
	if err := r.call(ctx, "miner_setEtherbase", []any{address}, &ok); err != nil {
		return false, err
	}
	return ok, nil
}

func (r *RPCClient) ConfirmedBalance(ctx context.Context, address string, confirmations int) (*big.Int, uint64, error) {
	address = normalizeAddress(address)
	if !isValidAddress(address) {
		return nil, 0, fmt.Errorf("invalid balance address %q", address)
	}
	head, err := r.BlockNumber(ctx)
	if err != nil {
		return nil, 0, err
	}
	confirmed := head
	if confirmations > 0 {
		if head < uint64(confirmations) {
			return nil, head, fmt.Errorf("head block %d has fewer than %d confirmations", head, confirmations)
		}
		confirmed = head - uint64(confirmations)
	}
	var balanceHex string
	if err := r.call(ctx, "eth_getBalance", []any{address, fmt.Sprintf("0x%x", confirmed)}, &balanceHex); err != nil {
		return nil, confirmed, err
	}
	balance, ok := new(big.Int).SetString(strings.TrimPrefix(balanceHex, "0x"), 16)
	if !ok {
		return nil, confirmed, fmt.Errorf("invalid balance result %q", balanceHex)
	}
	return balance, confirmed, nil
}

func (r *RPCClient) SendPayment(ctx context.Context, from, to string, amountAntd float64, passphrase string) (string, error) {
	from = normalizeAddress(from)
	to = normalizeAddress(to)
	if !isValidAddress(from) {
		return "", fmt.Errorf("invalid payout from address %q", from)
	}
	if !isValidAddress(to) {
		return "", fmt.Errorf("invalid payout to address %q", to)
	}
	txArgs := map[string]any{"from": from, "to": to, "value": antdToWeiHex(amountAntd)}
	var tx string
	if passphrase != "" {
		err := r.call(ctx, "tkm_sendTransactionWithPassphrase", []any{txArgs, passphrase}, &tx)
		return tx, err
	}
	err := r.call(ctx, "eth_sendTransaction", []any{txArgs}, &tx)
	return tx, err
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func weiToAntd(wei *big.Int) float64 {
	if wei == nil {
		return 0
	}
	antd, _ := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18)).Float64()
	return round(antd)
}

func antdToWeiHex(amount float64) string {
	return "0x" + antdToWeiInt(amount).Text(16)
}

func antdToWeiInt(amount float64) *big.Int {
	wei := new(big.Float).Mul(big.NewFloat(amount), big.NewFloat(1e18))
	i, _ := wei.Int(nil)
	return i
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
      <table><thead><tr><th>Wallet</th><th>Confirmed ANTD</th><th>Pending Round ANTD</th><th>Total ANTD</th></tr></thead><tbody id="balances"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Workers</h2>
      <table><thead><tr><th>Wallet</th><th>Worker</th><th>Accepted</th><th>Rejected</th><th>Round Shares</th><th>Last Seen</th></tr></thead><tbody id="miners"></tbody></table>
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
      $('miners').innerHTML = s.miners.map(m => row([m.wallet, m.worker || '-', m.acceptedShares, m.rejectedShares, m.roundShares || 0, new Date(m.lastSeen).toLocaleString()])).join('') || row(['No workers connected', '', '', '', '', '']);
      const wallets = Array.from(new Set([...Object.keys(s.balances || {}), ...Object.keys(s.pendingBalances || {})]));
      document.getElementById("balances").innerHTML = wallets.map(w => row([w, (s.balances || {})[w] || 0, (s.pendingBalances || {})[w] || 0, (((s.balances || {})[w] || 0) + ((s.pendingBalances || {})[w] || 0)).toFixed(8)])).join("") || row(["No balances yet", "0", "0", "0"]);
      $('payments').innerHTML = (s.payments || []).map(p => row([p.wallet, p.amountAntd, p.status, p.txHash || '-'])).join('') || row(['No payouts yet', '', '', '']);
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

const adminHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{POOL_NAME}} Admin</title>
  <style>
    :root { color-scheme: light; --bg:#f5f7fb; --ink:#141821; --muted:#5b6472; --line:#d8dee8; --panel:#fff; --green:#12715b; --red:#b42318; --blue:#174ea6; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; }
    header { background:#151922; color:#fff; padding:20px 28px; display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap; }
    h1 { margin:0; font-size:24px; letter-spacing:0; }
    main { max-width:1260px; margin:0 auto; padding:24px; }
    .grid { display:grid; gap:14px; grid-template-columns:repeat(4, minmax(0, 1fr)); }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }
    .metric { min-height:112px; }
    .label { color:var(--muted); font-size:12px; text-transform:uppercase; font-weight:750; }
    .value { margin-top:8px; font-size:24px; font-weight:780; overflow-wrap:anywhere; }
    .section { margin-top:18px; }
    .section h2 { margin:0 0 12px; font-size:17px; }
    table { width:100%; border-collapse:collapse; }
    th, td { padding:9px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; }
    code { background:#eef2f7; border:1px solid var(--line); border-radius:5px; padding:2px 5px; }
    button, a.button { border:1px solid #0f4ea8; background:var(--blue); color:white; border-radius:6px; padding:9px 12px; font-weight:700; cursor:pointer; text-decoration:none; display:inline-block; }
    button:disabled { opacity:.55; cursor:wait; }
    .ok { color:var(--green); font-weight:750; }
    .bad { color:var(--red); font-weight:750; }
    .muted { color:var(--muted); }
    .row { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .split { display:grid; gap:14px; grid-template-columns:1fr 1fr; }
    @media (max-width: 920px) { .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } .split { grid-template-columns:1fr; } main { padding:16px; } }
    @media (max-width: 560px) { .grid { grid-template-columns:1fr; } header { padding:18px; } .value { font-size:20px; } }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{{POOL_NAME}} Admin</h1>
      <div class="muted">Pool operations and payout state</div>
    </div>
    <div class="row">
      <a class="button" href="/">Dashboard</a>
      <button id="refresh">Refresh</button>
      <button id="runPayments">Run Payments</button>
    </div>
  </header>
  <main>
    <div class="grid">
      <div class="panel metric"><div class="label">Pool Wallet Latest</div><div class="value" id="latestBalance">loading</div><div class="muted" id="latestBlock"></div></div>
      <div class="panel metric"><div class="label">Confirmed Spendable</div><div class="value" id="spendableBalance">loading</div><div class="muted" id="confirmedBlock"></div></div>
      <div class="panel metric"><div class="label">Miner Balance Owed</div><div class="value" id="owedBalance">0</div><div class="muted" id="pendingBalance"></div></div>
      <div class="panel metric"><div class="label">Redis State</div><div class="value" id="redisStatus">loading</div><div class="muted" id="redisBytes"></div></div>
    </div>

    <section class="section split">
      <div class="panel">
        <h2>Pool Wallet</h2>
        <table><tbody id="walletRows"></tbody></table>
      </div>
      <div class="panel">
        <h2>Runtime</h2>
        <table><tbody id="runtimeRows"></tbody></table>
      </div>
    </section>

    <section class="section panel">
      <h2>Payout Configuration</h2>
      <table><tbody id="payoutRows"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Miner Balances</h2>
      <table><thead><tr><th>Wallet</th><th>Confirmed ANTD</th><th>Pending Round ANTD</th><th>Total ANTD</th></tr></thead><tbody id="balances"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Workers</h2>
      <table><thead><tr><th>Wallet</th><th>Worker</th><th>Accepted</th><th>Rejected</th><th>Round Shares</th><th>Last Seen</th></tr></thead><tbody id="miners"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Recent Payouts</h2>
      <table><thead><tr><th>Wallet</th><th>Amount</th><th>Status</th><th>Transaction</th><th>Created</th></tr></thead><tbody id="payments"></tbody></table>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const money = (v) => (Number(v || 0)).toFixed(8) + ' ANTD';
    const yesno = (v) => v ? '<span class="ok">yes</span>' : '<span class="bad">no</span>';
    function row(cells) { return '<tr>' + cells.map(v => '<td>' + String(v ?? '') + '</td>').join('') + '</tr>'; }
    function kv(k, v) { return '<tr><th>' + k + '</th><td>' + String(v ?? '') + '</td></tr>'; }
    function errText(v) { return v ? '<span class="bad">' + String(v) + '</span>' : ''; }
    async function load() {
      const res = await fetch('/api/admin/status');
      const s = await res.json();
      const b = s.poolWalletBalance || {};
      $('latestBalance').innerHTML = b.latestError ? errText(b.latestError) : money(b.latestAntd);
      $('latestBlock').textContent = b.latestBlock !== undefined ? 'block ' + b.latestBlock : '';
      $('spendableBalance').innerHTML = b.confirmedError ? errText(b.confirmedError) : money(b.spendableAntd);
      $('confirmedBlock').textContent = b.confirmedBlock !== undefined ? 'confirmed block ' + b.confirmedBlock : '';
      $('owedBalance').textContent = money(s.totalConfirmedMinerBalanceAntd);
      $('pendingBalance').textContent = 'pending round ' + money(s.totalPendingRoundAntd);
      $('redisStatus').innerHTML = s.redis && s.redis.ok ? '<span class="ok">online</span>' : '<span class="bad">offline</span>';
      $('redisBytes').textContent = s.redis && s.redis.ok ? String(s.redis.stateBytes || 0) + ' bytes saved' : ((s.redis && s.redis.error) || '');
      $('walletRows').innerHTML = kv('Pool wallet', s.poolWallet) + kv('Latest balance', b.latestError ? errText(b.latestError) : money(b.latestAntd)) + kv('Confirmed balance', b.confirmedError ? errText(b.confirmedError) : money(b.confirmedAntd)) + kv('Reserve', money(s.payoutReserveAntd)) + kv('Spendable', b.confirmedError ? errText(b.confirmedError) : money(b.spendableAntd)) + kv('Password configured', yesno(s.poolWalletPasswordConfigured)) + kv('Daemon coinbase', s.daemonCoinbaseError ? errText(s.daemonCoinbaseError) : s.daemonCoinbase) + kv('Rewards go to pool wallet', yesno(s.poolWalletIsDaemonCoinbase));
      $('runtimeRows').innerHTML = kv('HTTP', s.http) + kv('Stratum', s.stratum) + kv('Node RPC', s.nodeRPC) + kv('Work method', s.workMethod) + kv('Daemon coinbase', s.daemonCoinbaseError ? errText(s.daemonCoinbaseError) : s.daemonCoinbase) + kv('Current height', (s.work && s.work.height) || 0) + kv('Total shares', s.totalShares) + kv('Workers', s.workerCount) + kv('Uptime seconds', s.uptimeSeconds) + kv('Redis', (s.redis && s.redis.addr) + ' db ' + (s.redis && s.redis.db) + ' key ' + (s.redis && s.redis.stateKey));
      $('payoutRows').innerHTML = kv('Auto pay', yesno(s.autoPay)) + kv('Payment mode', s.paymentMode) + kv('Block reward', money(s.blockRewardAntd)) + kv('Pool fee', s.feePercent + '%') + kv('Minimum payout', money(s.minPayoutAntd)) + kv('Maximum per tx', money(s.maxPayoutPerTxAntd)) + kv('Payment interval', s.paymentIntervalSeconds + ' seconds') + kv('Confirmations for scheduled pay', s.paymentConfirmations) + kv('Recent payment records', s.paymentCount);
      const wallets = Array.from(new Set([...Object.keys(s.balances || {}), ...Object.keys(s.pendingBalances || {})]));
      $('balances').innerHTML = wallets.map(w => {
        const confirmed = (s.balances || {})[w] || 0;
        const pending = (s.pendingBalances || {})[w] || 0;
        return row([w, money(confirmed), money(pending), money(confirmed + pending)]);
      }).join('') || row(['No balances yet', money(0), money(0), money(0)]);
      $('miners').innerHTML = (s.miners || []).map(m => row([m.wallet, m.worker || '-', m.acceptedShares, m.rejectedShares, m.roundShares || 0, new Date(m.lastSeen).toLocaleString()])).join('') || row(['No workers connected', '', '', '', '', '']);
      $('payments').innerHTML = (s.payments || []).slice().reverse().slice(0, 50).map(p => row([p.wallet, money(p.amountAntd), p.status, p.txHash || '-', new Date(p.createdAt).toLocaleString()])).join('') || row(['No payouts yet', '', '', '', '']);
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

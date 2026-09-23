package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xproxy "golang.org/x/net/proxy"
)

type Config struct {
	PoolName                  string  `json:"poolName"`
	ListenHTTP                string  `json:"listenHTTP"`
	PublicURL                 string  `json:"publicURL"`
	ExplorerURL               string  `json:"explorerURL"`
	ListenStratum             string  `json:"listenStratum"`
	PublicStratum             string  `json:"publicStratum"`
	NodeRPC                   string  `json:"nodeRPC"`
	WorkMethod                string  `json:"workMethod"`
	PoolWallet                string  `json:"poolWallet"`
	PoolWalletPassword        string  `json:"poolWalletPassword"`
	AdminPassword             string  `json:"adminPassword"`
	RedisAddr                 string  `json:"redisAddr"`
	RedisPassword             string  `json:"redisPassword"`
	RedisDB                   int     `json:"redisDB"`
	RedisStateKey             string  `json:"redisStateKey"`
	BlockRewardAntd           float64 `json:"blockRewardAntd"`
	NetworkFeePercent         float64 `json:"networkFeePercent"`
	MinPayoutAntd             float64 `json:"minPayoutAntd"`
	MaxPayoutPerTxAntd        float64 `json:"maxPayoutPerTxAntd"`
	PaymentMode               string  `json:"paymentMode"`
	AutoPay                   bool    `json:"autoPay"`
	PaymentIntervalSeconds    int     `json:"paymentIntervalSeconds"`
	PaymentConfirmations      int     `json:"paymentConfirmations"`
	PayoutReserveAntd         float64 `json:"payoutReserveAntd"`
	RPCTimeoutSeconds         int     `json:"rpcTimeoutSeconds"`
	WorkPollIntervalMs        int     `json:"workPollIntervalMs"`
	ShareTarget               string  `json:"shareTarget"`
	PrivacyCommitmentTime     uint64  `json:"privacyCommitmentTime"`
	QuantumResistantTime      uint64  `json:"quantumResistantTime"`
	ShieldedPayoutProverURL   string  `json:"shieldedPayoutProverURL"`
	ShieldedPayoutProverToken string  `json:"shieldedPayoutProverToken"`
	ShieldedPayoutChangeCode  string  `json:"shieldedPayoutChangeCode"`
	ShieldedPayoutApplication string  `json:"shieldedPayoutApplication"`
	TorSOCKS5Proxy            string  `json:"torSocks5Proxy"`
	PrivacyStrict             bool    `json:"privacyStrict"`
	OnionOnly                 bool    `json:"onionOnly"`
}

type PayoutState struct {
	Balances          map[string]float64 `json:"balances"`
	Payments          []Payment          `json:"payments"`
	Miners            map[string]Miner   `json:"miners"`
	RecipientViewKeys map[string]string  `json:"recipientViewKeys,omitempty"`
	TotalShares       uint64             `json:"totalShares"`
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
	Wallet           string    `json:"wallet"`
	Amount           float64   `json:"amountAntd"`
	Status           string    `json:"status"`
	TxHash           string    `json:"txHash,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
	RecipientViewKey string    `json:"recipientViewKey,omitempty"`
}

type RPCHeader struct {
	Number    uint64
	Timestamp uint64
}

type NetworkStatus struct {
	LatestBlock                    uint64 `json:"latestBlock"`
	LatestTimestamp                uint64 `json:"latestTimestamp"`
	HeadError                      string `json:"headError,omitempty"`
	PrivacyCommitmentTime          uint64 `json:"privacyCommitmentTime"`
	PrivacyCommitmentActive        bool   `json:"privacyCommitmentActive"`
	PrivacyCommitmentSource        string `json:"privacyCommitmentSource"`
	PrivacyCommitmentError         string `json:"privacyCommitmentError,omitempty"`
	QuantumResistantTime           uint64 `json:"quantumResistantTime"`
	QuantumResistantActive         bool   `json:"quantumResistantActive"`
	PoolWalletAlgorithm            string `json:"poolWalletAlgorithm,omitempty"`
	PoolWalletAlgorithmError       string `json:"poolWalletAlgorithmError,omitempty"`
	ShieldedPayoutProverConfigured bool   `json:"shieldedPayoutProverConfigured"`
	ShieldedPayoutsEnabled         bool   `json:"shieldedPayoutsEnabled"`
	ShieldedPayoutProverReady      bool   `json:"shieldedPayoutProverReady"`
	ShieldedPayoutProverError      string `json:"shieldedPayoutProverError,omitempty"`
	ShieldedPayoutAvailableNotes   int    `json:"shieldedPayoutAvailableNotes"`
	ShieldedPayoutMaxNoteWei       string `json:"shieldedPayoutMaxNoteWei,omitempty"`
	PayoutTxType                   string `json:"payoutTxType"`
	PayoutReady                    bool   `json:"payoutReady"`
	PayoutBlockedReason            string `json:"payoutBlockedReason,omitempty"`
}

const (
	pqTxTypeHex                         = "0x6"
	pqAlgorithmMLDSA87                  = "ML-DSA-87"
	tkmPrivacyQuantumActivationUnix     = uint64(1786341600) // 2026-08-10 06:00:00 UTC
	privacyTransparentPayoutBlockReason = "privacy commitments are active; transparent pool payouts are disabled until a shielded payout prover is configured"
	shieldedMaxPayoutPerTxAntd          = 18.44674407 // floor(MaxUint64 wei / 1e18) to the pool's 8 decimal places
)

type Pool struct {
	cfg               Config
	rpc               *RPCClient
	mu                sync.RWMutex
	work              Work
	miners            map[string]*Miner
	balances          map[string]float64
	payments          []Payment
	jobs              map[string]Work
	sessions          map[*stratumSession]struct{}
	recipientViewKeys map[string]string
	logMu             sync.Mutex
	lastLog           map[string]logThrottle
	started           time.Time
	shares            atomic.Uint64
	paying            atomic.Bool
}

type logThrottle struct {
	last       time.Time
	suppressed int
}

type stratumSession struct {
	enc    *json.Encoder
	mu     sync.Mutex
	wallet string
	worker string
	xmrig  bool
	rpcID  string
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

	log.Printf("%s dashboard listening on %s bind=%s", cfg.PoolName, cfg.PublicURL, cfg.ListenHTTP)
	if err := pool.serveHTTP(ctx); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func loadConfig(path string) (Config, error) {
	cfg := Config{
		PoolName:               "TKM Pool",
		ListenHTTP:             "127.0.0.1:8080",
		PublicURL:              "http://127.0.0.1:8080",
		ExplorerURL:            "",
		ListenStratum:          "0.0.0.0:3333",
		PublicStratum:          "127.0.0.1:3333",
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
		WorkPollIntervalMs:     500,
		ShareTarget:            "0x000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		PrivacyCommitmentTime:  tkmPrivacyQuantumActivationUnix,
		QuantumResistantTime:   tkmPrivacyQuantumActivationUnix,
		TorSOCKS5Proxy:         "",
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	if strings.HasPrefix(strings.ToLower(cfg.ListenHTTP), "http://") || strings.HasPrefix(strings.ToLower(cfg.ListenHTTP), "https://") {
		if cfg.PublicURL == "" {
			cfg.PublicURL = cfg.ListenHTTP
		}
		if parsed, err := url.Parse(cfg.ListenHTTP); err == nil && parsed.Port() != "" {
			cfg.ListenHTTP = "0.0.0.0:" + parsed.Port()
		} else {
			cfg.ListenHTTP = "0.0.0.0:33230"
		}
	}
	if cfg.OnionOnly {
		if cfg.ListenHTTP != "" {
			bound, err := bindLoopback(cfg.ListenHTTP)
			if err != nil {
				return cfg, fmt.Errorf("onionOnly requires a host:port HTTP listener: %w", err)
			}
			cfg.ListenHTTP = bound
		}
		if cfg.ListenStratum != "" {
			bound, err := bindLoopback(cfg.ListenStratum)
			if err != nil {
				return cfg, fmt.Errorf("onionOnly requires a host:port stratum listener: %w", err)
			}
			cfg.ListenStratum = bound
		}
		if cfg.PublicStratum != "" {
			host, _, err := net.SplitHostPort(cfg.PublicStratum)
			if err != nil || (!isLoopbackEndpoint(host) && !strings.HasSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), ".onion")) {
				return cfg, errors.New("onionOnly requires a loopback or .onion public stratum endpoint")
			}
		}
	}
	if cfg.PublicURL == "" {
		cfg.PublicURL = "http://" + cfg.ListenHTTP
	}
	if cfg.OnionOnly && !onionOrLoopbackURL(cfg.PublicURL) {
		return cfg, errors.New("onionOnly requires a loopback or .onion publicURL")
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	cfg.ExplorerURL = strings.TrimRight(cfg.ExplorerURL, "/")
	cfg.ShieldedPayoutProverURL = strings.TrimSpace(cfg.ShieldedPayoutProverURL)
	cfg.ShieldedPayoutProverToken = strings.TrimSpace(cfg.ShieldedPayoutProverToken)
	cfg.ShieldedPayoutChangeCode = strings.TrimSpace(cfg.ShieldedPayoutChangeCode)
	if cfg.PublicStratum == "" {
		cfg.PublicStratum = cfg.ListenStratum
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
	if cfg.WorkPollIntervalMs <= 0 {
		cfg.WorkPollIntervalMs = 500
	}
	if cfg.WorkPollIntervalMs < 100 {
		cfg.WorkPollIntervalMs = 100
	}
	if cfg.WorkMethod == "" {
		cfg.WorkMethod = "miner"
	}
	if cfg.ShareTarget == "" {
		cfg.ShareTarget = "0x000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	cfg.ShareTarget = normalizeHex(cfg.ShareTarget)
	if cfg.PrivacyCommitmentTime == 0 {
		cfg.PrivacyCommitmentTime = tkmPrivacyQuantumActivationUnix
	}
	if cfg.QuantumResistantTime == 0 {
		cfg.QuantumResistantTime = tkmPrivacyQuantumActivationUnix
	}
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
	if err := validatePrivacyConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func bindLoopback(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort("127.0.0.1", port), nil
}

func onionOrLoopbackURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	return isLoopbackEndpoint(host) || strings.HasSuffix(host, ".onion")
}

func validatePrivacyConfig(cfg Config) error {
	if cfg.TorSOCKS5Proxy == "" {
		if cfg.PrivacyStrict || cfg.OnionOnly {
			return errors.New("privacyStrict/onionOnly requires torSocks5Proxy")
		}
		return nil
	}
	u, err := url.Parse(cfg.TorSOCKS5Proxy)
	if err != nil || u.Scheme != "socks5" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("torSocks5Proxy must be a plain socks5://host:port URL")
	}
	if cfg.PrivacyStrict || cfg.OnionOnly {
		for name, endpoint := range map[string]string{"nodeRPC": cfg.NodeRPC, "prover": cfg.ShieldedPayoutProverURL} {
			if endpoint == "" {
				continue
			}
			parsed, err := url.Parse(endpoint)
			if err != nil || parsed.Host == "" {
				return fmt.Errorf("invalid %s endpoint", name)
			}
			if isLoopbackEndpoint(parsed.Hostname()) {
				continue
			}
			onion := strings.HasSuffix(strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")), ".onion")
			if cfg.OnionOnly && !onion {
				return fmt.Errorf("onionOnly requires a .onion endpoint for %s (loopback is allowed)", name)
			}
			if !cfg.OnionOnly && !onion && parsed.Scheme != "https" {
				return fmt.Errorf("privacyStrict requires HTTPS or .onion for %s", name)
			}
		}
	}
	return nil
}

func isLoopbackEndpoint(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func newPrivacyHTTPClient(cfg Config) (*http.Client, error) {
	if err := validatePrivacyConfig(cfg); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if cfg.TorSOCKS5Proxy != "" {
		u, _ := url.Parse(cfg.TorSOCKS5Proxy)
		dialer, err := xproxy.SOCKS5("tcp", u.Host, nil, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if isLoopbackEndpoint(host) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			result := make(chan struct {
				conn net.Conn
				err  error
			}, 1)
			go func() {
				conn, err := dialer.Dial(network, address)
				result <- struct {
					conn net.Conn
					err  error
				}{conn, err}
			}()
			select {
			case r := <-result:
				return r.conn, r.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return &http.Client{Transport: transport, Timeout: time.Duration(cfg.RPCTimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func NewPool(cfg Config) *Pool {
	httpClient, err := newPrivacyHTTPClient(cfg)
	if err != nil {
		panic(err)
	}
	pool := &Pool{
		cfg:               cfg,
		rpc:               &RPCClient{endpoint: cfg.NodeRPC, method: strings.ToLower(cfg.WorkMethod), client: httpClient},
		miners:            make(map[string]*Miner),
		balances:          make(map[string]float64),
		recipientViewKeys: make(map[string]string),
		jobs:              make(map[string]Work),
		sessions:          make(map[*stratumSession]struct{}),
		lastLog:           make(map[string]logThrottle),
		started:           time.Now(),
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
		for _, miner := range state.Miners {
			miner.Wallet = normalizeAddress(miner.Wallet)
			if !isValidAddress(miner.Wallet) {
				log.Printf("dropping invalid miner wallet=%s", miner.Wallet)
				continue
			}
			p.mergeMinerLocked(miner)
		}
	}
	if state.RecipientViewKeys != nil {
		p.recipientViewKeys = make(map[string]string, len(state.RecipientViewKeys))
		for wallet, key := range state.RecipientViewKeys {
			wallet = normalizeAddress(wallet)
			if isValidAddress(wallet) && isValidViewKey(key) {
				p.recipientViewKeys[wallet] = strings.ToLower(strings.TrimPrefix(key, "0x"))
			}
		}
	}
	if state.TotalShares > 0 {
		p.shares.Store(state.TotalShares)
	}
}

func (p *Pool) mergeMinerLocked(miner Miner) {
	miner.Wallet = normalizeAddress(miner.Wallet)
	key := minerKey(miner.Wallet, miner.Worker)
	existing := p.miners[key]
	if existing == nil {
		m := miner
		p.miners[key] = &m
		return
	}
	existing.AcceptedShares += miner.AcceptedShares
	existing.RejectedShares += miner.RejectedShares
	existing.RoundShares += miner.RoundShares
	if miner.LastSeen.After(existing.LastSeen) {
		existing.LastSeen = miner.LastSeen
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
		Balances:          make(map[string]float64, len(p.balances)),
		Payments:          append([]Payment{}, p.payments...),
		Miners:            make(map[string]Miner, len(p.miners)),
		RecipientViewKeys: make(map[string]string, len(p.recipientViewKeys)),
		TotalShares:       p.shares.Load(),
	}
	for wallet, balance := range p.balances {
		state.Balances[wallet] = round(balance)
	}
	for key, miner := range p.miners {
		if miner != nil {
			state.Miners[key] = *miner
		}
	}
	for wallet, key := range p.recipientViewKeys {
		state.RecipientViewKeys[wallet] = key
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
	interval := time.Duration(p.cfg.WorkPollIntervalMs) * time.Millisecond
	log.Printf("work polling interval=%s", interval)
	ticker := time.NewTicker(interval)
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
	log.Printf("stratum listening on %s public=%s", p.cfg.ListenStratum, p.cfg.PublicStratum)

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
	viewKey := ""

	for {
		var req stratumRequest
		if err := dec.Decode(&req); err != nil {
			if err != io.EOF {
				log.Printf("stratum decode failed: %v", err)
			}
			return
		}

		switch req.Method {
		case "login":
			wallet, worker, viewKey = parseXMRigLoginRecipient(req.Params)
			if wallet != "" {
				session.mu.Lock()
				session.wallet = wallet
				session.worker = worker
				session.xmrig = true
				session.rpcID = sessionID
				session.mu.Unlock()
				log.Printf("xmrig miner connected miner=%s", minerLabel(wallet, worker))
				p.touchMiner(wallet, worker, viewKey)
			}
			result := map[string]any{"id": sessionID, "extensions": []string{"algo"}}
			if wallet != "" {
				if job := p.xmrigJobObject(session); job != nil {
					result["job"] = job
				}
			}
			session.write(map[string]any{"id": jsonRPCResponseID(req.ID), "jsonrpc": "2.0", "result": result, "error": nil})
		case "submit":
			if wallet == "" {
				session.write(map[string]any{"id": jsonRPCResponseID(req.ID), "jsonrpc": "2.0", "result": false, "error": map[string]any{"code": -1, "message": "unauthorized"}})
				continue
			}
			ok, reason := p.submitShare(context.Background(), wallet, worker, req.Params, session)
			if ok {
				session.write(map[string]any{"id": jsonRPCResponseID(req.ID), "jsonrpc": "2.0", "result": map[string]any{"status": "OK"}, "error": nil})
			} else {
				session.write(map[string]any{"id": jsonRPCResponseID(req.ID), "jsonrpc": "2.0", "result": nil, "error": map[string]any{"code": -1, "message": reason}})
				p.logEvery("xmrigreject:"+minerKey(wallet, worker), 10*time.Second, "xmrig share rejected miner=%s", minerLabel(wallet, worker))
			}
		case "keepalived":
			session.write(map[string]any{"id": jsonRPCResponseID(req.ID), "jsonrpc": "2.0", "result": map[string]any{"status": "KEEPALIVED"}, "error": nil})
		case "mining.subscribe":
			session.write(map[string]any{
				"id":     req.ID,
				"result": []any{[]any{[]any{"mining.notify", sessionID}}, sessionID, 4},
				"error":  nil,
			})
			p.notifyCurrent(session)
		case "mining.authorize":
			wallet, worker, viewKey = parseAuthorizeRecipient(req.Params)
			if wallet != "" {
				session.mu.Lock()
				session.wallet = wallet
				session.worker = worker
				session.mu.Unlock()
				log.Printf("miner connected miner=%s", minerLabel(wallet, worker))
			}
			p.touchMiner(wallet, worker, viewKey)
			session.write(map[string]any{"id": req.ID, "result": wallet != "", "error": nil})
		case "mining.submit":
			if wallet == "" {
				session.write(map[string]any{"id": req.ID, "result": false, "error": "unauthorized"})
				continue
			}
			ok, reason := p.submitShare(context.Background(), wallet, worker, req.Params, session)
			session.write(map[string]any{"id": req.ID, "result": ok, "error": shareResponseError(ok, reason)})
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
	session.mu.Lock()
	xmrigMode := session.xmrig
	session.mu.Unlock()
	if xmrigMode {
		if job := p.xmrigJobObjectForWork(work); job != nil {
			session.write(map[string]any{
				"id":      nil,
				"jsonrpc": "2.0",
				"method":  "job",
				"params":  job,
			})
		}
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
			fmt.Sprintf("0x%x", work.Height),
			work.Target,
		},
	})
}

func (p *Pool) xmrigJobObject(session *stratumSession) map[string]any {
	p.mu.RLock()
	work := p.work
	p.mu.RUnlock()
	return p.xmrigJobObjectForWork(work)
}

func (p *Pool) xmrigJobObjectForWork(work Work) map[string]any {
	if work.SealHash == "" {
		return nil
	}
	return map[string]any{
		"job_id":    jobID(work),
		"algo":      "rx/tkm",
		"blob":      tkmXMRigBlob(work),
		"seed_hash": trimHex(work.SeedHash),
		"target":    xmrigShareTarget(p.cfg.ShareTarget),
		"height":    work.Height,
	}
}

func jobID(work Work) string {
	return work.SealHash
}

func parseAuthorize(raw json.RawMessage) (string, string) {
	wallet, worker, _ := parseAuthorizeRecipient(raw)
	return wallet, worker
}

func parseAuthorizeRecipient(raw json.RawMessage) (string, string, string) {
	var params []string
	_ = json.Unmarshal(raw, &params)
	if len(params) == 0 {
		return "", "", ""
	}
	return parseMinerLoginRecipient(params[0])
}

func parseXMRigLogin(raw json.RawMessage) (string, string) {
	wallet, worker, _ := parseXMRigLoginRecipient(raw)
	return wallet, worker
}

func parseXMRigLoginRecipient(raw json.RawMessage) (string, string, string) {
	var params struct {
		Login string `json:"login"`
	}
	_ = json.Unmarshal(raw, &params)
	return parseMinerLoginRecipient(params.Login)
}

func jsonRPCResponseID(id any) any {
	switch v := id.(type) {
	case float64:
		if math.Trunc(v) == v {
			return int64(v)
		}
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return id
}

func parseMinerLogin(user string) (string, string) {
	wallet, worker, _ := parseMinerLoginRecipient(user)
	return wallet, worker
}

func parseMinerLoginRecipient(user string) (string, string, string) {
	user = strings.TrimSpace(user)
	if recipient, err := parseShieldedPaymentCode(user); err == nil {
		return recipient.Address, "", recipient.ViewKey
	}
	separator := strings.LastIndex(user, ".")
	walletText, worker := user, ""
	if separator > 0 {
		walletText, worker = user[:separator], strings.TrimSpace(user[separator+1:])
		if recipient, err := parseShieldedPaymentCode(walletText); err == nil {
			return recipient.Address, worker, recipient.ViewKey
		}
	}
	wallet := normalizeAddress(walletText)
	if !isValidAddress(wallet) {
		log.Printf("invalid miner payout wallet rejected wallet=%s", walletText)
		return "", worker, ""
	}
	return wallet, worker, ""
}

func minerKey(wallet, worker string) string {
	return wallet + "." + worker
}

func (p *Pool) touchMiner(wallet, worker, viewKey string) {
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
	if isValidViewKey(viewKey) {
		p.recipientViewKeys[wallet] = strings.ToLower(strings.TrimPrefix(viewKey, "0x"))
	}
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

func workerOrDash(worker string) string {
	if strings.TrimSpace(worker) == "" {
		return "-"
	}
	return worker
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

func (p *Pool) submitShare(ctx context.Context, wallet, worker string, raw json.RawMessage, session *stratumSession) (bool, string) {
	job, nonce, digest := parseShareSubmission(raw)
	p.mu.RLock()
	work := p.work
	currentJob := jobID(work)
	staleJob := job == "" || job != currentJob
	p.mu.RUnlock()
	if staleJob {
		p.logEvery("stale:"+minerKey(wallet, worker), time.Minute, "stale shares miner=%s job=%s current=%s action=renotify", minerLabel(wallet, worker), shortID(job), shortID(currentJob))
		if session != nil && !session.xmrig {
			p.notify(session, work)
		}
		p.recordRejectedShare(wallet, worker)
		return false, "stale or unknown job"
	}

	reason := "invalid nonce or digest"
	shareAccepted := false
	blockAccepted := false
	if work.SealHash != "" {
		nonce = normalizeTKMNonce(nonce)
		digest = normalizeHex(digest)
		if nonce != "" && isValidHash(digest) {
			computed, err := p.rpc.VerifyShareRaw(ctx, nonce, work.SealHash, digest)
			if err != nil {
				reason = "RandomX verification unavailable; see pool logs"
				if strings.Contains(err.Error(), "submitted digest does not match") {
					reason = "RandomX hash mismatch: submitted result differs from node calculation"
				} else if strings.Contains(err.Error(), "stale or unknown") {
					reason = "stale or unknown job at node"
				}
				p.logEvery("verify:"+minerKey(wallet, worker), 10*time.Second, "share verification failed miner=%s nonce=%s digest=%s err=%v", minerLabel(wallet, worker), nonce, digest, err)
			} else if randomXMeetsTarget(computed, p.cfg.ShareTarget) {
				shareAccepted = true
			} else {
				reason = "share difficulty below pool target"
				p.logEvery("lowdiff:"+minerKey(wallet, worker), 10*time.Second, "share low-diff miner=%s nonce=%s", minerLabel(wallet, worker), shortID(nonce))
			}
			if shareAccepted && randomXMeetsTarget(computed, work.Target) {
				var err error
				blockAccepted, err = p.rpc.SubmitWorkRaw(ctx, nonce, work.SealHash, computed)
				if err != nil {
					log.Printf("block submit failed miner=%s height=%d job=%s err=%v", minerLabel(wallet, worker), work.Height, shortID(jobID(work)), err)
				} else if !blockAccepted {
					p.logEvery("blockreject:"+minerKey(wallet, worker), 10*time.Second, "block rejected miner=%s height=%d job=%s nonce=%s", minerLabel(wallet, worker), work.Height, shortID(jobID(work)), shortID(nonce))
				} else {
					log.Printf("block mined address=%s worker=%s height=%d job=%s nonce=%s", wallet, workerOrDash(worker), work.Height, shortID(jobID(work)), shortID(nonce))
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
	if shareAccepted {
		return true, ""
	}
	return false, reason
}

func parseShareSubmission(raw json.RawMessage) (job, nonce, digest string) {
	var params []string
	if err := json.Unmarshal(raw, &params); err == nil && len(params) >= 4 {
		return strings.TrimSpace(params[1]), params[2], params[3]
	}
	var obj struct {
		ID     string `json:"id"`
		JobID  string `json:"job_id"`
		Nonce  string `json:"nonce"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return strings.TrimSpace(obj.JobID), obj.Nonce, obj.Result
	}
	return "", "", ""
}

func normalizeTKMNonce(nonce string) string {
	nonce = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(nonce), "0x"), "0X")
	if !isHexString(nonce) {
		return ""
	}
	switch len(nonce) {
	case 8:
		return "0x00000000" + strings.ToLower(nonce)
	case 16:
		return "0x" + strings.ToLower(nonce)
	default:
		return ""
	}
}

func tkmXMRigBlob(work Work) string {
	seal := trimHex(work.SealHash)
	if len(seal) != 64 || !isHexString(seal) {
		return ""
	}
	return seal + "0000000000000000"
}

func trimHex(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	return strings.ToLower(s)
}

func xmrigShareTarget(target string) string {
	hexTarget := trimHex(target)
	if len(hexTarget) == 64 && isHexString(hexTarget) {
		return hexTarget
	}
	if len(hexTarget) == 16 && isHexString(hexTarget) {
		return strings.Repeat("0", 48) + hexTarget
	}
	return strings.Repeat("f", 64)
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
		return "0x" + strings.ToLower(s)
	}
	return strings.TrimSpace(s)
}

func isValidAddress(s string) bool {
	s = normalizeAddress(s)
	return len(s) == 42 && strings.HasPrefix(strings.ToLower(s), "0x") && isHexString(s[2:])
}

const shieldedPaymentChainID = uint64(8979)

type shieldedPaymentCode struct {
	Version uint8  `json:"v"`
	ChainID uint64 `json:"c"`
	Address string `json:"a"`
	ViewKey string `json:"k"`
}

type shieldedRecipient struct {
	Address string
	ViewKey string
}

// parseShieldedPaymentCode accepts the public tkmshield2 code produced by
// gtkm and the native wallet. Its view key is public recipient metadata, not
// a spending key.
func parseShieldedPaymentCode(code string) (shieldedRecipient, error) {
	code = strings.TrimSpace(code)
	const prefix = "tkmshield2."
	if !strings.HasPrefix(strings.ToLower(code), prefix) {
		return shieldedRecipient{}, errors.New("not a Shield2 payment code")
	}
	payload, err := base64.RawURLEncoding.DecodeString(code[len(prefix):])
	if err != nil {
		return shieldedRecipient{}, errors.New("invalid Shield2 payment code")
	}
	var decoded shieldedPaymentCode
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded.Version != 2 || decoded.ChainID != shieldedPaymentChainID {
		return shieldedRecipient{}, errors.New("Shield2 payment code is not for TKM mainnet")
	}
	address := normalizeAddress(decoded.Address)
	if !isValidAddress(address) || !isValidViewKey(decoded.ViewKey) {
		return shieldedRecipient{}, errors.New("invalid Shield2 payment code recipient")
	}
	return shieldedRecipient{Address: address, ViewKey: strings.ToLower(strings.TrimPrefix(decoded.ViewKey, "0x"))}, nil
}

func isValidViewKey(key string) bool {
	key = strings.TrimPrefix(strings.TrimSpace(key), "0x")
	return len(key) == 64 && isHexString(key)
}

func isValidHash(s string) bool {
	s = normalizeHex(s)
	return len(s) == 66 && strings.HasPrefix(strings.ToLower(s), "0x") && isHexString(s[2:])
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
	confirmations := time.NewTicker(15 * time.Second)
	defer confirmations.Stop()
	ticker := time.NewTicker(time.Duration(p.cfg.PaymentIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-confirmations.C:
			p.refreshLiquidityReceipts(ctx)
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

func (p *Pool) shieldedPayoutProverConfigured() bool {
	return strings.TrimSpace(p.cfg.ShieldedPayoutProverURL) != ""
}

type ShieldedPayoutRequest struct {
	RequestID             string    `json:"requestId"`
	ApplicationData       string    `json:"applicationData,omitempty"`
	PoolWallet            string    `json:"poolWallet"`
	To                    string    `json:"to"`
	AmountAntd            float64   `json:"amountAntd"`
	AmountWei             string    `json:"amountWei"`
	PayoutTxType          string    `json:"payoutTxType,omitempty"`
	RecipientViewKey      string    `json:"recipientViewKey"`
	ChangeViewKey         string    `json:"changeViewKey"`
	PrivacyCommitmentTime uint64    `json:"privacyCommitmentTime"`
	QuantumResistantTime  uint64    `json:"quantumResistantTime"`
	CreatedAt             time.Time `json:"createdAt"`
}

type ShieldedPayoutResponse struct {
	TxHash string `json:"txHash"`
	Hash   string `json:"hash,omitempty"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type ShieldedPayoutProverHealth struct {
	OK                  bool   `json:"ok"`
	PayoutReady         bool   `json:"payoutReady"`
	HasSpendableNotes   bool   `json:"hasSpendableNotes"`
	AvailableNoteCount  int    `json:"availableNoteCount"`
	AvailableNoteMaxWei string `json:"availableNoteMaxWei"`
	NoteInventoryError  string `json:"noteInventoryError"`
	StartupError        string `json:"startupError"`
	SignMode            string `json:"signMode"`
	HasKeystore         bool   `json:"hasKeystore"`
}

func (p *Pool) shieldedPayoutRequestID(payment Payment) string {
	wallet := normalizeAddress(payment.Wallet)
	sequence := 0

	p.mu.RLock()
	for _, existing := range p.payments {
		if strings.EqualFold(normalizeAddress(existing.Wallet), wallet) && existing.Status == "sent" {
			sequence++
		}
	}
	p.mu.RUnlock()

	payload := fmt.Sprintf("%s|%s|%s|%.8f|%d|shielded-payout", p.cfg.RedisStateKey, normalizeAddress(p.cfg.PoolWallet), wallet, round(payment.Amount), sequence)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func effectiveShieldedPayoutAmount(amount float64) float64 {
	amount = round(amount)
	if amount <= 0 {
		return 0
	}
	if amount > shieldedMaxPayoutPerTxAntd || antdToWeiInt(amount).BitLen() > 64 {
		return shieldedMaxPayoutPerTxAntd
	}
	return amount
}

func effectiveShieldedPayoutAmountForNote(amount float64, maxNoteWeiText string) float64 {
	amount = effectiveShieldedPayoutAmount(amount)
	if amount <= 0 {
		return 0
	}
	maxNoteWei, ok := parseBigFlexible(maxNoteWeiText)
	if !ok || maxNoteWei.Sign() <= 0 {
		return 0
	}
	maxNoteAntd := weiToAntdFloor(maxNoteWei)
	if maxNoteAntd <= 0 {
		return 0
	}
	amount = round(minFloat(amount, maxNoteAntd))
	for amount > 0 && antdToWeiInt(amount).Cmp(maxNoteWei) > 0 {
		amount = round(amount - 0.00000001)
	}
	return amount
}

func effectiveMaxPayoutPerTxAntd(maxPayout float64, shielded bool) float64 {
	maxPayout = round(maxPayout)
	if maxPayout <= 0 {
		return 0
	}
	if shielded && (maxPayout > shieldedMaxPayoutPerTxAntd || antdToWeiInt(maxPayout).BitLen() > 64) {
		return shieldedMaxPayoutPerTxAntd
	}
	return maxPayout
}

func shieldedPayoutHealthURL(endpoint string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid shielded payout prover URL %q", endpoint)
	}
	parsed.Path = "/healthz"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func (p *Pool) shieldedPayoutProverHealth(ctx context.Context) (ShieldedPayoutProverHealth, error) {
	endpoint, err := shieldedPayoutHealthURL(p.cfg.ShieldedPayoutProverURL)
	if err != nil {
		return ShieldedPayoutProverHealth{}, err
	}
	if p.rpc == nil || p.rpc.client == nil {
		return ShieldedPayoutProverHealth{}, errors.New("shielded payout HTTP client is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ShieldedPayoutProverHealth{}, err
	}
	if token := strings.TrimSpace(p.cfg.ShieldedPayoutProverToken); token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := p.rpc.client.Do(req)
	if err != nil {
		return ShieldedPayoutProverHealth{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return ShieldedPayoutProverHealth{}, fmt.Errorf("health returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out ShieldedPayoutProverHealth
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ShieldedPayoutProverHealth{}, err
	}
	return out, nil
}

func (p *Pool) refreshLiquidityReceipts(ctx context.Context) {
	p.mu.RLock()
	pending := make([]Payment, 0)
	for _, payment := range p.payments {
		if payment.Status == "unconfirmed: shielded liquidity deposit" && isValidHash(payment.TxHash) {
			pending = append(pending, payment)
		}
	}
	p.mu.RUnlock()
	for _, payment := range pending {
		var receipt *struct {
			Status          string `json:"status"`
			BlockNumber     string `json:"blockNumber"`
			TransactionHash string `json:"transactionHash"`
		}
		if err := p.rpc.call(ctx, "eth_getTransactionReceipt", []any{payment.TxHash}, &receipt); err != nil || receipt == nil || receipt.BlockNumber == "" || !strings.EqualFold(receipt.TransactionHash, payment.TxHash) {
			continue
		}
		status, ok := parseBigFlexible(receipt.Status)
		if !ok {
			continue
		}
		label := "failed: shielded liquidity deposit reverted"
		if status.Uint64() == 1 {
			label = "confirmed: shielded liquidity deposit"
		}
		p.mu.Lock()
		for i := range p.payments {
			if p.payments[i].TxHash == payment.TxHash && p.payments[i].Status == "unconfirmed: shielded liquidity deposit" {
				p.payments[i].Status = label
			}
		}
		p.savePayoutStateLocked()
		p.mu.Unlock()
	}
}

func (p *Pool) createShieldedLiquidityNote(ctx context.Context, amount float64) error {
	endpoint := strings.TrimSpace(p.cfg.ShieldedPayoutProverURL)
	if endpoint == "" {
		return errors.New("shielded payout prover URL is not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	u.Path = strings.TrimSuffix(u.Path, "/payout") + "/deposit"
	change, err := p.shieldedPayoutChangeRecipient()
	if err != nil {
		return err
	}
	amount = minFloat(round(amount), shieldedMaxPayoutPerTxAntd)
	wei := antdToWeiInt(amount)
	body, err := json.Marshal(map[string]any{"requestId": fmt.Sprintf("pool-liquidity-%d", time.Now().UnixNano()), "amountAntd": amount, "amountWei": "0x" + wei.Text(16), "from": normalizeAddress(p.cfg.PoolWallet), "to": normalizeAddress(p.cfg.PoolWallet), "recipientViewKey": "0x" + change.ViewKey, "createdAt": time.Now().UTC()})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	if t := strings.TrimSpace(p.cfg.ShieldedPayoutProverToken); t != "" {
		req.Header.Set("authorization", "Bearer "+t)
	}
	resp, err := p.rpc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	// The prover returns HTTP 400 when submission is still pending, but the
	// transaction hash is authoritative and must be tracked as unconfirmed.
	var result struct {
		TxHash string `json:"txHash"`
	}
	_ = json.Unmarshal(b, &result)
	if strings.TrimSpace(result.TxHash) != "" && isValidHash(result.TxHash) {
		p.mu.Lock()
		p.payments = append(p.payments, Payment{Wallet: normalizeAddress(p.cfg.PoolWallet), Amount: amount, TxHash: result.TxHash, Status: "unconfirmed: shielded liquidity deposit", CreatedAt: time.Now()})
		p.savePayoutStateLocked()
		p.mu.Unlock()
		p.refreshLiquidityReceipts(ctx)
		return nil
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("deposit HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (p *Pool) sendShieldedPayment(ctx context.Context, payment Payment, txType string) (string, error) {
	endpoint := strings.TrimSpace(p.cfg.ShieldedPayoutProverURL)
	if endpoint == "" {
		return "", errors.New("shielded payout prover URL is not configured")
	}
	if p.rpc == nil || p.rpc.client == nil {
		return "", errors.New("shielded payout HTTP client is not configured")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid shielded payout prover URL %q", endpoint)
	}

	to := normalizeAddress(payment.Wallet)
	if !isValidAddress(to) {
		return "", fmt.Errorf("invalid shielded payout address %q", payment.Wallet)
	}
	if !isValidViewKey(payment.RecipientViewKey) {
		return "", fmt.Errorf("miner %s must reconnect with a tkmshield2 payment code before receiving shielded payouts", to)
	}
	change, err := p.shieldedPayoutChangeRecipient()
	if err != nil {
		return "", err
	}
	payment.Amount = effectiveShieldedPayoutAmount(payment.Amount)
	if payment.Amount <= 0 {
		return "", errors.New("shielded payout amount must be positive")
	}
	amountWei := antdToWeiInt(payment.Amount)
	if amountWei.Sign() <= 0 || amountWei.BitLen() > 64 {
		return "", fmt.Errorf("shielded payout amount %.8f exceeds uint64 wei circuit limit", payment.Amount)
	}
	reqBody, err := json.Marshal(ShieldedPayoutRequest{
		RequestID:             p.shieldedPayoutRequestID(payment),
		ApplicationData:       p.shieldedPayoutApplicationData(payment),
		PoolWallet:            normalizeAddress(p.cfg.PoolWallet),
		To:                    to,
		AmountAntd:            round(payment.Amount),
		AmountWei:             "0x" + amountWei.Text(16),
		PayoutTxType:          txType,
		RecipientViewKey:      "0x" + strings.ToLower(strings.TrimPrefix(payment.RecipientViewKey, "0x")),
		ChangeViewKey:         "0x" + change.ViewKey,
		PrivacyCommitmentTime: p.cfg.PrivacyCommitmentTime,
		QuantumResistantTime:  p.cfg.QuantumResistantTime,
		CreatedAt:             payment.CreatedAt,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	if token := strings.TrimSpace(p.cfg.ShieldedPayoutProverToken); token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}

	resp, err := p.rpc.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var pending struct {
			TxHash string `json:"txHash"`
		}
		_ = json.Unmarshal(body, &pending)
		if isValidHash(pending.TxHash) {
			return strings.ToLower(normalizeHex(pending.TxHash)), nil
		}
		return "", fmt.Errorf("prover returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out ShieldedPayoutResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != "" {
		return "", errors.New(out.Error)
	}
	txHash := out.TxHash
	if txHash == "" {
		txHash = out.Hash
	}
	txHash = strings.ToLower(normalizeHex(txHash))
	if !isValidHash(txHash) {
		return "", fmt.Errorf("prover returned invalid tx hash %q status=%q", out.TxHash, out.Status)
	}
	return txHash, nil
}

func (p *Pool) shieldedPayoutApplicationData(payment Payment) string {
	prefix := strings.TrimSpace(p.cfg.ShieldedPayoutApplication)
	if prefix == "" {
		prefix = "TKM_POOL_PAYOUT_V1"
	}
	// The prover feeds applicationData directly into the shielded circuit and
	// requires a 0x-prefixed hexadecimal byte string.
	return "0x" + hex.EncodeToString([]byte(prefix+":"+p.shieldedPayoutRequestID(payment)))
}

func (p *Pool) shieldedPayoutChangeRecipient() (shieldedRecipient, error) {
	change, err := parseShieldedPaymentCode(p.cfg.ShieldedPayoutChangeCode)
	if err != nil {
		return shieldedRecipient{}, fmt.Errorf("shieldedPayoutChangeCode is required for recoverable pool change notes: %w", err)
	}
	if !strings.EqualFold(change.Address, normalizeAddress(p.cfg.PoolWallet)) {
		return shieldedRecipient{}, errors.New("shieldedPayoutChangeCode address does not match poolWallet")
	}
	return change, nil
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
			due = append(due, Payment{Wallet: wallet, RecipientViewKey: p.recipientViewKeys[wallet], Amount: round(minFloat(balance, p.cfg.MaxPayoutPerTxAntd)), Status: "pending", CreatedAt: time.Now()})
		}
	}
	p.mu.RUnlock()
	if len(due) == 0 {
		return
	}

	network := p.networkStatus(ctx)
	if !network.PayoutReady {
		p.recordPaymentStatuses(due, "waiting: "+network.PayoutBlockedReason)
		return
	}
	if network.PrivacyCommitmentActive && network.ShieldedPayoutsEnabled {
		p.payDueShielded(ctx, due, network.PayoutTxType)
		return
	}

	confirmedBalance, blockNumber, err := p.rpc.ConfirmedBalance(ctx, p.cfg.PoolWallet, confirmations)
	if err != nil {
		p.recordPaymentStatuses(due, "waiting: confirmed pool balance check failed: "+err.Error())
		return
	}
	pendingBalance, err := p.rpc.BalanceAt(ctx, p.cfg.PoolWallet, "pending")
	if err != nil {
		p.recordPaymentStatuses(due, "waiting: pending pool balance check failed: "+err.Error())
		return
	}
	availableBalance := minBigInt(confirmedBalance, pendingBalance)
	spendable := new(big.Int).Sub(availableBalance, antdToWeiInt(p.cfg.PayoutReserveAntd))
	if spendable.Sign() <= 0 {
		p.recordPaymentStatuses(due, fmt.Sprintf("waiting: pool balance below reserve at block %d", blockNumber))
		return
	}

	for _, payment := range due {
		amountWei := antdToWeiInt(payment.Amount)
		if amountWei.Cmp(spendable) > 0 {
			spendableAntd := weiToAntd(spendable)
			if spendableAntd < p.cfg.MinPayoutAntd {
				p.recordPaymentStatuses([]Payment{payment}, fmt.Sprintf("waiting: low pool wallet balance at block %d", blockNumber))
				continue
			}
			payment.Amount = round(minFloat(spendableAntd, p.cfg.MaxPayoutPerTxAntd))
			amountWei = antdToWeiInt(payment.Amount)
		}
		feeWei, err := p.rpc.PaymentFee(ctx, p.cfg.PoolWallet, payment.Wallet, payment.Amount, network.PayoutTxType)
		if err != nil {
			if isInsufficientFundsError(err) {
				p.recordPaymentStatuses([]Payment{payment}, fmt.Sprintf("waiting: low pool wallet balance at block %d", blockNumber))
			} else {
				p.recordPaymentStatuses([]Payment{payment}, "waiting: payout fee estimate failed: "+err.Error())
			}
			continue
		}
		payoutCost := new(big.Int).Add(amountWei, feeWei)
		if payoutCost.Cmp(spendable) > 0 {
			valueBudget := new(big.Int).Sub(spendable, feeWei)
			spendableAntd := weiToAntd(valueBudget)
			if spendableAntd >= p.cfg.MinPayoutAntd {
				payment.Amount = round(minFloat(spendableAntd, p.cfg.MaxPayoutPerTxAntd))
				amountWei = antdToWeiInt(payment.Amount)
				feeWei, err = p.rpc.PaymentFee(ctx, p.cfg.PoolWallet, payment.Wallet, payment.Amount, network.PayoutTxType)
				if err != nil {
					if isInsufficientFundsError(err) {
						p.recordPaymentStatuses([]Payment{payment}, fmt.Sprintf("waiting: low pool wallet balance at block %d", blockNumber))
					} else {
						p.recordPaymentStatuses([]Payment{payment}, "waiting: payout fee estimate failed: "+err.Error())
					}
					continue
				}
				payoutCost = new(big.Int).Add(amountWei, feeWei)
				if payoutCost.Cmp(spendable) > 0 {
					p.recordPaymentStatuses([]Payment{payment}, fmt.Sprintf("waiting: low pool wallet balance at block %d", blockNumber))
					continue
				}
			} else {
				p.recordPaymentStatuses([]Payment{payment}, fmt.Sprintf("waiting: low pool wallet balance at block %d", blockNumber))
				continue
			}
		}
		tx, err := p.rpc.SendPayment(ctx, p.cfg.PoolWallet, payment.Wallet, payment.Amount, p.cfg.PoolWalletPassword, network.PayoutTxType)
		p.mu.Lock()
		if err != nil {
			if isInsufficientFundsError(err) {
				payment.Status = fmt.Sprintf("waiting: low pool wallet balance at block %d", blockNumber)
			} else {
				payment.Status = "failed: " + err.Error()
			}
		} else {
			payment.Status = "sent"
			payment.TxHash = tx
			p.balances[payment.Wallet] = round(p.balances[payment.Wallet] - payment.Amount)
			if p.balances[payment.Wallet] <= 0 {
				delete(p.balances, payment.Wallet)
			}
			spendable.Sub(spendable, payoutCost)
		}
		p.payments = append(p.payments, payment)
		p.savePayoutStateLocked()
		p.mu.Unlock()
	}
}

func (p *Pool) payDueShielded(ctx context.Context, due []Payment, txType string) {
	for _, payment := range due {
		originalAmount := payment.Amount
		health, err := p.shieldedPayoutProverHealth(ctx)
		if err != nil {
			p.recordPaymentStatuses([]Payment{payment}, "waiting: shielded payout prover health check failed: "+err.Error())
			continue
		}
		switch {
		case !health.OK:
			p.recordPaymentStatuses([]Payment{payment}, "waiting: "+firstNonEmpty(health.StartupError, "shielded payout prover is not ready"))
			continue
		case health.NoteInventoryError != "":
			p.recordPaymentStatuses([]Payment{payment}, "waiting: shielded payout note inventory error: "+health.NoteInventoryError)
			continue
		case !health.HasSpendableNotes || health.AvailableNoteCount == 0:
			if err := p.createShieldedLiquidityNote(ctx, payment.Amount); err != nil {
				p.recordPaymentStatuses([]Payment{payment}, "waiting: daemon-funded shielded note creation: "+err.Error())
			}
			continue
		case strings.EqualFold(strings.TrimSpace(health.SignMode), "proof-only") || !health.HasKeystore:
			p.recordPaymentStatuses([]Payment{payment}, "waiting: shielded payout prover is not configured with a signing keystore")
			continue
		}
		payment.Amount = effectiveShieldedPayoutAmountForNote(payment.Amount, health.AvailableNoteMaxWei)
		if payment.Amount <= 0 {
			p.recordPaymentStatuses([]Payment{payment}, "waiting: shielded payout prover has no spendable shielded note for this amount")
			continue
		}
		if payment.Amount < p.cfg.MinPayoutAntd {
			if err := p.createShieldedLiquidityNote(ctx, originalAmount); err != nil {
				p.recordPaymentStatuses([]Payment{payment}, "waiting: daemon-funded shielded note creation: "+err.Error())
			}
			continue
		}
		if payment.Amount != round(originalAmount) {
			log.Printf("shielded payout chunked wallet=%s requested=%.8f chunk=%.8f circuitMax=%.8f maxNoteWei=%s", payment.Wallet, originalAmount, payment.Amount, shieldedMaxPayoutPerTxAntd, health.AvailableNoteMaxWei)
		}
		tx, err := p.sendShieldedPayment(ctx, payment, txType)
		p.mu.Lock()
		if err != nil {
			payment.Status = "waiting: shielded prover: " + err.Error()
		} else {
			payment.Status = "sent"
			payment.TxHash = tx
			p.balances[payment.Wallet] = round(p.balances[payment.Wallet] - payment.Amount)
			if p.balances[payment.Wallet] <= 0 {
				delete(p.balances, payment.Wallet)
			}
			log.Printf("shielded payout sent wallet=%s amount=%.8f tx=%s", payment.Wallet, payment.Amount, tx)
		}
		p.payments = append(p.payments, payment)
		p.savePayoutStateLocked()
		p.mu.Unlock()
	}
}

func (p *Pool) networkStatus(ctx context.Context) NetworkStatus {
	status := NetworkStatus{
		PrivacyCommitmentTime:          p.cfg.PrivacyCommitmentTime,
		PrivacyCommitmentSource:        "configured",
		QuantumResistantTime:           p.cfg.QuantumResistantTime,
		ShieldedPayoutProverConfigured: p.shieldedPayoutProverConfigured(),
		PayoutReady:                    true,
	}

	if header, err := p.rpc.LatestHeader(ctx); err != nil {
		status.HeadError = err.Error()
	} else {
		status.LatestBlock = header.Number
		status.LatestTimestamp = header.Timestamp
		if status.PrivacyCommitmentTime > 0 && header.Timestamp >= status.PrivacyCommitmentTime {
			status.PrivacyCommitmentActive = true
			status.PrivacyCommitmentSource = "timestamp"
		}
		if status.QuantumResistantTime > 0 && header.Timestamp >= status.QuantumResistantTime {
			status.QuantumResistantActive = true
		}
	}
	if activationTime, ok, err := p.rpc.PrivacyCommitmentActivationTime(ctx); err != nil {
		status.PrivacyCommitmentError = err.Error()
	} else if ok {
		status.PrivacyCommitmentTime = activationTime
		if status.LatestTimestamp >= activationTime {
			status.PrivacyCommitmentActive = true
			status.PrivacyCommitmentSource = "node-config"
		}
	}
	if active, err := p.rpc.PrivacyCommitmentActive(ctx); err != nil {
		if status.PrivacyCommitmentError == "" {
			status.PrivacyCommitmentError = err.Error()
		}
	} else {
		status.PrivacyCommitmentActive = active
		status.PrivacyCommitmentSource = "rpc"
		status.PrivacyCommitmentError = ""
	}

	if isValidAddress(p.cfg.PoolWallet) {
		if algorithm, err := p.rpc.AccountAlgorithm(ctx, p.cfg.PoolWallet); err != nil {
			status.PoolWalletAlgorithmError = err.Error()
		} else {
			status.PoolWalletAlgorithm = algorithm
		}
	}
	if status.QuantumResistantActive {
		status.PayoutTxType = pqTxTypeHex
	}
	status.ShieldedPayoutsEnabled = status.PrivacyCommitmentActive && status.ShieldedPayoutProverConfigured

	var blockers []string
	if status.ShieldedPayoutsEnabled {
		if _, err := p.shieldedPayoutChangeRecipient(); err != nil {
			blockers = append(blockers, err.Error())
		}
		health, err := p.shieldedPayoutProverHealth(ctx)
		if err != nil {
			status.ShieldedPayoutProverError = err.Error()
			blockers = append(blockers, "shielded payout prover health check failed: "+err.Error())
		} else {
			status.ShieldedPayoutAvailableNotes = health.AvailableNoteCount
			status.ShieldedPayoutMaxNoteWei = health.AvailableNoteMaxWei
			status.ShieldedPayoutProverError = firstNonEmpty(health.NoteInventoryError, health.StartupError)
			switch {
			case !health.OK:
				reason := firstNonEmpty(health.StartupError, "shielded payout prover is not ready")
				blockers = append(blockers, reason)
			case health.NoteInventoryError != "":
				blockers = append(blockers, "shielded payout note inventory error: "+health.NoteInventoryError)
			case strings.EqualFold(strings.TrimSpace(health.SignMode), "proof-only") || !health.HasKeystore:
				blockers = append(blockers, "shielded payout prover requires a signing keystore; proof-only mode cannot send pool payouts")
			default:
				status.ShieldedPayoutProverReady = true
			}
		}
	}
	if status.PrivacyCommitmentActive && !status.ShieldedPayoutsEnabled {
		blockers = append(blockers, privacyTransparentPayoutBlockReason)
	}
	if status.QuantumResistantActive && !status.ShieldedPayoutsEnabled {
		switch {
		case status.PoolWalletAlgorithm == pqAlgorithmMLDSA87:
		case status.PoolWalletAlgorithm != "":
			blockers = append(blockers, fmt.Sprintf("quantum-resistant fork is active; pool wallet uses %s, expected %s", status.PoolWalletAlgorithm, pqAlgorithmMLDSA87))
		case p.cfg.PoolWalletPassword != "" && status.PoolWalletAlgorithmError != "":
			blockers = append(blockers, "quantum-resistant fork is active; cannot verify pool wallet algorithm: "+status.PoolWalletAlgorithmError)
		}
	}
	if len(blockers) > 0 {
		status.PayoutReady = false
		status.PayoutBlockedReason = strings.Join(blockers, "; ")
	}
	return status
}

func (p *Pool) serveHTTP(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write(renderPoolHTML(indexHTML, p.cfg.PoolName))
	})
	mux.HandleFunc("/user.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write(renderPoolHTML(userHTML, p.cfg.PoolName))
	})
	mux.HandleFunc("/admin.html", func(w http.ResponseWriter, r *http.Request) {
		if !p.requireAdmin(w, r) {
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write(renderPoolHTML(adminHTML, p.cfg.PoolName))
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		p.writeStatus(w)
	})
	mux.HandleFunc("/api/user/status", func(w http.ResponseWriter, r *http.Request) {
		p.writeUserStatus(w, r)
	})
	mux.HandleFunc("/api/admin/status", func(w http.ResponseWriter, r *http.Request) {
		if !p.requireAdmin(w, r) {
			return
		}
		p.writeAdminStatus(w, r)
	})
	mux.HandleFunc("/api/payments/run", func(w http.ResponseWriter, r *http.Request) {
		if !p.requireAdmin(w, r) {
			return
		}

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

// renderPoolHTML keeps the dashboard pages self-contained. The translator is
// embedded in the response so the pool UI also works for miners with no
// external network access (including onion-only deployments).
func renderPoolHTML(template, poolName string) []byte {
	page := strings.ReplaceAll(template, "{{POOL_NAME}}", poolName)
	page = strings.Replace(page, "</body>", poolI18nScript+"</body>", 1)
	return []byte(page)
}

func (p *Pool) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if p.cfg.AdminPassword == "" {
		http.Error(w, "admin password is not configured; set adminPassword in config.json", http.StatusServiceUnavailable)
		return false
	}
	_, password, ok := r.BasicAuth()
	if ok && subtle.ConstantTimeCompare([]byte(password), []byte(p.cfg.AdminPassword)) == 1 {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="TKM Pool Admin"`)
	http.Error(w, "admin authentication required", http.StatusUnauthorized)
	return false
}

func (p *Pool) sessionCountsLocked() (int, int) {
	connected := len(p.sessions)
	authorized := 0
	for session := range p.sessions {
		session.mu.Lock()
		if session.wallet != "" {
			authorized++
		}
		session.mu.Unlock()
	}
	return connected, authorized
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
	connectedSessions, authorizedSessions := p.sessionCountsLocked()
	p.mu.RUnlock()
	network := p.networkStatus(context.Background())

	resp := map[string]any{
		"poolName":           p.cfg.PoolName,
		"paymentMode":        p.cfg.PaymentMode,
		"workMethod":         p.cfg.WorkMethod,
		"autoPay":            p.cfg.AutoPay,
		"minPayoutAntd":      p.cfg.MinPayoutAntd,
		"feePercent":         p.cfg.NetworkFeePercent,
		"stratum":            p.cfg.PublicStratum,
		"stratumBind":        p.cfg.ListenStratum,
		"http":               p.cfg.ListenHTTP,
		"publicURL":          p.cfg.PublicURL,
		"explorerURL":        p.cfg.ExplorerURL,
		"nodeRPC":            p.cfg.NodeRPC,
		"poolWallet":         p.cfg.PoolWallet,
		"uptimeSeconds":      int(time.Since(p.started).Seconds()),
		"totalShares":        p.shares.Load(),
		"connectedSessions":  connectedSessions,
		"authorizedSessions": authorizedSessions,
		"workerCount":        len(miners),
		"work":               work,
		"miners":             miners,
		"balances":           balances,
		"pendingBalances":    pendingBalances,
		"payments":           publicPayments(payments),
		"network":            publicNetworkStatus(network),
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *Pool) writeUserStatus(w http.ResponseWriter, r *http.Request) {
	walletInput := strings.TrimSpace(r.URL.Query().Get("address"))
	wallet := normalizeAddress(walletInput)
	if recipient, err := parseShieldedPaymentCode(walletInput); err == nil {
		wallet = recipient.Address
	}
	if !isValidAddress(wallet) {
		http.Error(w, "invalid wallet address", http.StatusBadRequest)
		return
	}

	p.mu.RLock()
	confirmed := round(p.balances[wallet])
	pendingBalances := p.pendingBalancesLocked()
	pending := round(pendingBalances[wallet])
	miners := make([]Miner, 0)
	var accepted, rejected, roundShares uint64
	for _, m := range p.miners {
		if m != nil && strings.EqualFold(m.Wallet, wallet) {
			miners = append(miners, *m)
			accepted += m.AcceptedShares
			rejected += m.RejectedShares
			roundShares += m.RoundShares
		}
	}
	payments := make([]Payment, 0)
	var paid, waiting, failed float64
	for _, payment := range p.payments {
		if strings.EqualFold(normalizeAddress(payment.Wallet), wallet) {
			payments = append(payments, payment)
			switch {
			case payment.Status == "sent":
				paid += payment.Amount
			case strings.HasPrefix(payment.Status, "failed"):
				failed += payment.Amount
			default:
				waiting += payment.Amount
			}
		}
	}
	work := p.work
	p.mu.RUnlock()
	network := p.networkStatus(r.Context())

	resp := map[string]any{
		"poolName":            p.cfg.PoolName,
		"wallet":              wallet,
		"confirmedBalance":    confirmed,
		"pendingRoundBalance": pending,
		"totalBalance":        round(confirmed + pending),
		"totalPaid":           round(paid),
		"totalWaiting":        round(waiting),
		"totalFailed":         round(failed),
		"acceptedShares":      accepted,
		"rejectedShares":      rejected,
		"roundShares":         roundShares,
		"workers":             miners,
		"payments":            publicPayments(payments),
		"explorerURL":         p.cfg.ExplorerURL,
		"work":                work,
		"minPayoutAntd":       p.cfg.MinPayoutAntd,
		"maxPayoutPerTxAntd":  p.cfg.MaxPayoutPerTxAntd,
		"network":             publicNetworkStatus(network),
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
	connectedSessions, authorizedSessions := p.sessionCountsLocked()
	p.mu.RUnlock()

	daemonCoinbase := ""
	daemonCoinbaseError := ""
	if coinbase, err := p.rpc.Coinbase(r.Context()); err != nil {
		daemonCoinbaseError = err.Error()
	} else {
		daemonCoinbase = normalizeAddress(coinbase)
	}
	network := p.networkStatus(r.Context())

	poolWalletBalance := map[string]any{}
	if network.PrivacyCommitmentActive && network.ShieldedPayoutsEnabled {
		poolWalletBalance["shieldedPayoutMode"] = true
		poolWalletBalance["payoutStatus"] = "shielded prover ready"
	}
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
		pendingWei, pendingErr := p.rpc.BalanceAt(r.Context(), p.cfg.PoolWallet, "pending")
		if pendingErr != nil {
			poolWalletBalance["pendingError"] = pendingErr.Error()
			pendingWei = confirmedWei
		} else {
			poolWalletBalance["pendingAntd"] = weiToAntd(pendingWei)
		}
		availableWei := minBigInt(confirmedWei, pendingWei)
		spendableWei := new(big.Int).Sub(availableWei, antdToWeiInt(p.cfg.PayoutReserveAntd))
		if spendableWei.Sign() < 0 {
			spendableWei = new(big.Int)
		}
		spendableAntd := weiToAntd(spendableWei)
		poolWalletBalance["confirmedAntd"] = confirmedAntd
		poolWalletBalance["confirmedBlock"] = confirmedBlock
		poolWalletBalance["availableAntd"] = weiToAntd(availableWei)
		poolWalletBalance["spendableAntd"] = spendableAntd
		poolWalletBalance["lowBalance"] = false
		poolWalletBalance["payoutStatus"] = "ready"
		poolWalletBalance["totalOwedAntd"] = sumFloatMap(balances)

		if network.PrivacyCommitmentActive && network.ShieldedPayoutsEnabled {
			poolWalletBalance["shieldedPayoutMode"] = true
			poolWalletBalance["payoutStatus"] = "shielded prover ready"
			poolWalletBalance["shieldedMaxPayoutPerTxAntd"] = shieldedMaxPayoutPerTxAntd
			for wallet, balance := range balances {
				if balance < p.cfg.MinPayoutAntd {
					continue
				}
				nextAmount := effectiveShieldedPayoutAmount(minFloat(balance, p.cfg.MaxPayoutPerTxAntd))
				poolWalletBalance["nextPayoutWallet"] = wallet
				poolWalletBalance["nextPayoutAntd"] = nextAmount
				break
			}
		} else {
			for wallet, balance := range balances {
				if balance < p.cfg.MinPayoutAntd {
					continue
				}
				nextAmount := round(minFloat(balance, p.cfg.MaxPayoutPerTxAntd))
				poolWalletBalance["nextPayoutWallet"] = wallet
				poolWalletBalance["nextPayoutAntd"] = nextAmount
				feeWei, err := p.rpc.PaymentFee(r.Context(), p.cfg.PoolWallet, wallet, nextAmount, network.PayoutTxType)
				if err != nil {
					if isInsufficientFundsError(err) {
						poolWalletBalance["lowBalance"] = true
						poolWalletBalance["payoutStatus"] = "low pool wallet balance"
					} else {
						poolWalletBalance["feeEstimateError"] = err.Error()
					}
					break
				}
				spendableAfterFee := new(big.Int).Sub(spendableWei, feeWei)
				if spendableAfterFee.Sign() < 0 {
					spendableAfterFee = new(big.Int)
				}
				poolWalletBalance["estimatedTxFeeAntd"] = weiToAntd(feeWei)
				poolWalletBalance["spendableAfterFeeAntd"] = weiToAntd(spendableAfterFee)
				if new(big.Int).Add(antdToWeiInt(nextAmount), feeWei).Cmp(spendableWei) > 0 {
					poolWalletBalance["lowBalance"] = true
					poolWalletBalance["payoutStatus"] = "low pool wallet balance"
				} else {
					poolWalletBalance["payoutStatus"] = "next payout can be sent"
				}
				break
			}
		}
	}
	if !network.PayoutReady {
		poolWalletBalance["payoutBlocked"] = true
		poolWalletBalance["lowBalance"] = true
		poolWalletBalance["payoutStatus"] = network.PayoutBlockedReason
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
		"effectiveMaxPayoutPerTxAntd":    effectiveMaxPayoutPerTxAntd(p.cfg.MaxPayoutPerTxAntd, network.PrivacyCommitmentActive && network.ShieldedPayoutsEnabled),
		"paymentIntervalSeconds":         p.cfg.PaymentIntervalSeconds,
		"paymentConfirmations":           p.cfg.PaymentConfirmations,
		"payoutReserveAntd":              p.cfg.PayoutReserveAntd,
		"workPollIntervalMs":             p.cfg.WorkPollIntervalMs,
		"blockRewardAntd":                p.cfg.BlockRewardAntd,
		"feePercent":                     p.cfg.NetworkFeePercent,
		"stratum":                        p.cfg.PublicStratum,
		"stratumBind":                    p.cfg.ListenStratum,
		"http":                           p.cfg.ListenHTTP,
		"publicURL":                      p.cfg.PublicURL,
		"explorerURL":                    p.cfg.ExplorerURL,
		"nodeRPC":                        p.cfg.NodeRPC,
		"poolWallet":                     p.cfg.PoolWallet,
		"poolWalletPasswordConfigured":   p.cfg.PoolWalletPassword != "",
		"daemonCoinbase":                 daemonCoinbase,
		"daemonCoinbaseError":            daemonCoinbaseError,
		"poolWalletIsDaemonCoinbase":     daemonCoinbase != "" && strings.EqualFold(daemonCoinbase, p.cfg.PoolWallet),
		"uptimeSeconds":                  int(time.Since(p.started).Seconds()),
		"totalShares":                    totalShares,
		"workerCount":                    len(miners),
		"connectedSessions":              connectedSessions,
		"authorizedSessions":             authorizedSessions,
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
		"network":                        network,
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

func (r *RPCClient) callWithStateRetry(ctx context.Context, method string, params []any, result any) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		err = r.call(ctx, method, params, result)
		if err == nil || !isTransientStateReadError(err) {
			return err
		}
		delay := time.Duration(100*(attempt+1)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}

func isTransientStateReadError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "layer stale") || strings.Contains(msg, "missing trie node") || strings.Contains(msg, "getstateobject") || strings.Contains(msg, "historical state")
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

func (r *RPCClient) VerifyShareRaw(ctx context.Context, nonce, sealHash, digest string) (string, error) {
	if r.method != "randomx" && r.method != "auto" {
		return "", errors.New("daemon-side RandomX share verification requires workMethod randomx or auto")
	}
	var verified string
	if err := r.call(ctx, "randomx_verifyShareRaw", []any{nonce, sealHash, digest}, &verified); err != nil {
		return "", err
	}
	if len(trimHex(verified)) != 64 || !isHexString(trimHex(verified)) {
		return "", errors.New("daemon returned an invalid RandomX share digest")
	}
	return verified, nil
}

func (r *RPCClient) BlockNumber(ctx context.Context) (uint64, error) {
	var blockHex string
	if err := r.call(ctx, "eth_blockNumber", []any{}, &blockHex); err != nil {
		return 0, err
	}
	return parseUintFlexible(blockHex), nil
}

func (r *RPCClient) LatestHeader(ctx context.Context) (RPCHeader, error) {
	var header struct {
		Number    string `json:"number"`
		Timestamp string `json:"timestamp"`
	}
	if err := r.call(ctx, "eth_getHeaderByNumber", []any{"latest"}, &header); err != nil {
		if fallbackErr := r.call(ctx, "eth_getBlockByNumber", []any{"latest", false}, &header); fallbackErr != nil {
			return RPCHeader{}, fmt.Errorf("eth_getHeaderByNumber failed: %w; eth_getBlockByNumber failed: %v", err, fallbackErr)
		}
	}
	if header.Number == "" || header.Timestamp == "" {
		return RPCHeader{}, errors.New("latest header response missing number or timestamp")
	}
	return RPCHeader{Number: parseUintFlexible(header.Number), Timestamp: parseUintFlexible(header.Timestamp)}, nil
}

func (r *RPCClient) PrivacyCommitmentActivationTime(ctx context.Context) (uint64, bool, error) {
	var raw json.RawMessage
	if err := r.call(ctx, "tkmprivacy_commitmentActivationTime", []any{}, &raw); err != nil {
		return 0, false, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return parseUintFlexible(text), true, nil
	}
	var number uint64
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, true, nil
	}
	return 0, false, fmt.Errorf("invalid privacy activation time result %s", string(raw))
}

func (r *RPCClient) PrivacyCommitmentActive(ctx context.Context) (bool, error) {
	var active bool
	if err := r.call(ctx, "tkmprivacy_commitmentActive", []any{}, &active); err != nil {
		return false, err
	}
	return active, nil
}

func (r *RPCClient) AccountAlgorithm(ctx context.Context, address string) (string, error) {
	address = normalizeAddress(address)
	if !isValidAddress(address) {
		return "", fmt.Errorf("invalid account address %q", address)
	}
	var algorithm string
	if err := r.call(ctx, "tkm_accountAlgorithm", []any{address}, &algorithm); err != nil {
		return "", err
	}
	return algorithm, nil
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

func (r *RPCClient) BalanceAt(ctx context.Context, address, block string) (*big.Int, error) {
	address = normalizeAddress(address)
	if !isValidAddress(address) {
		return nil, fmt.Errorf("invalid balance address %q", address)
	}
	var balanceHex string
	if err := r.callWithStateRetry(ctx, "eth_getBalance", []any{address, block}, &balanceHex); err != nil {
		// Some daemon states cannot answer the synthetic pending tag while
		// pruning historical layers. Latest is safe for dashboard/payout checks.
		if isTransientStateReadError(err) {
			if fallbackErr := r.callWithStateRetry(ctx, "eth_getBalance", []any{address, "latest"}, &balanceHex); fallbackErr == nil {
				err = nil
			} else {
				return nil, fallbackErr
			}
		}
		if err != nil {
			return nil, err
		}
	}
	balance, ok := parseBigFlexible(balanceHex)
	if !ok {
		return nil, fmt.Errorf("invalid balance result %q", balanceHex)
	}
	return balance, nil
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
	balance, err := r.BalanceAt(ctx, address, fmt.Sprintf("0x%x", confirmed))
	if err != nil {
		return nil, confirmed, err
	}
	return balance, confirmed, nil
}

func (r *RPCClient) SendPayment(ctx context.Context, from, to string, amountAntd float64, passphrase string, txType string) (string, error) {
	from = normalizeAddress(from)
	to = normalizeAddress(to)
	if !isValidAddress(from) {
		return "", fmt.Errorf("invalid payout from address %q", from)
	}
	if !isValidAddress(to) {
		return "", fmt.Errorf("invalid payout to address %q", to)
	}
	txArgs := paymentTxArgs(from, to, amountAntd, txType)
	var tx string
	if passphrase != "" {
		err := r.call(ctx, "tkm_sendTransactionWithPassphrase", []any{txArgs, passphrase}, &tx)
		return tx, err
	}
	err := r.call(ctx, "eth_sendTransaction", []any{txArgs}, &tx)
	return tx, err
}

func (r *RPCClient) PaymentFee(ctx context.Context, from, to string, amountAntd float64, txType string) (*big.Int, error) {
	from = normalizeAddress(from)
	to = normalizeAddress(to)
	if !isValidAddress(from) {
		return nil, fmt.Errorf("invalid payout from address %q", from)
	}
	if !isValidAddress(to) {
		return nil, fmt.Errorf("invalid payout to address %q", to)
	}
	txArgs := paymentTxArgs(from, to, amountAntd, txType)
	var gasHex string
	if err := r.callWithStateRetry(ctx, "eth_estimateGas", []any{txArgs}, &gasHex); err != nil {
		return nil, err
	}
	gas, ok := parseBigFlexible(gasHex)
	if !ok {
		return nil, fmt.Errorf("invalid gas estimate result %q", gasHex)
	}
	var gasPriceHex string
	if err := r.call(ctx, "eth_gasPrice", []any{}, &gasPriceHex); err != nil {
		return nil, err
	}
	gasPrice, ok := parseBigFlexible(gasPriceHex)
	if !ok {
		return nil, fmt.Errorf("invalid gas price result %q", gasPriceHex)
	}
	return new(big.Int).Mul(gas, gasPrice), nil
}

func paymentTxArgs(from, to string, amountAntd float64, txType string) map[string]any {
	txArgs := map[string]any{"from": from, "to": to, "value": antdToWeiHex(amountAntd)}
	if txType != "" {
		txArgs["type"] = txType
	}
	return txArgs
}

func isInsufficientFundsError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "insufficient funds") || strings.Contains(msg, "overshot")
}

func minBigInt(a, b *big.Int) *big.Int {
	if a.Cmp(b) <= 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
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

func weiToAntdFloor(wei *big.Int) float64 {
	if wei == nil || wei.Sign() <= 0 {
		return 0
	}
	scaled := new(big.Int).Mul(new(big.Int).Set(wei), big.NewInt(100000000))
	scaled.Div(scaled, big.NewInt(1000000000000000000))
	antd, _ := new(big.Float).Quo(new(big.Float).SetInt(scaled), big.NewFloat(100000000)).Float64()
	return round(antd)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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

// randomXDigestMatches accepts the canonical node representation and XMRig's
// raw little-endian wire representation. The daemon-computed value is always
// used after this comparison, so a miner cannot choose the credited digest.
func randomXDigestMatches(computed, submitted string) bool {
	want := trimHex(computed)
	got := trimHex(submitted)
	if len(want) != 64 || len(got) != 64 || !isHexString(want) || !isHexString(got) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1 {
		return true
	}
	reversed := make([]byte, len(got))
	for i := 0; i < len(got); i += 2 {
		copy(reversed[i:i+2], got[len(got)-2-i:len(got)-i])
	}
	return subtle.ConstantTimeCompare([]byte(want), reversed) == 1
}

func parseUintFlexible(s string) uint64 {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.EqualFold(s[:2], "0x") {
		v, _ := strconv.ParseUint(s[2:], 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func parseBigFlexible(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.EqualFold(s[:2], "0x") {
		return new(big.Int).SetString(s[2:], 16)
	}
	return new(big.Int).SetString(s, 10)
}

func round(v float64) float64 {
	return math.Round(v*1e8) / 1e8
}

const poolI18nScript = `<script>
(function () {
  'use strict';
  var storageKey = 'tkmpool-language';
  var languages = [
    ['zh', '中文'], ['ru', 'Русский'], ['en', 'English'], ['ja', '日本語'],
    ['ko', '한국어'], ['es', 'Español'], ['fr', 'Français'], ['de', 'Deutsch'],
    ['pt', 'Português'], ['ar', 'العربية'], ['hi', 'हिन्दी'], ['it', 'Italiano'],
    ['tr', 'Türkçe'], ['vi', 'Tiếng Việt'], ['th', 'ไทย'], ['id', 'Bahasa Indonesia'],
    ['pl', 'Polski'], ['nl', 'Nederlands'], ['uk', 'Українська'], ['sw', 'Kiswahili']
  ];
  var base = {
    'Language':'Language', 'RandomX mining · Shield2-ready payouts':'RandomX mining · Shield2-ready payouts',
    'Miner Lookup':'Miner Lookup', 'Admin':'Admin', 'Refresh':'Refresh', 'Dashboard':'Dashboard',
    'Pool Shares':'Pool Shares', 'Connected Miners':'Connected Miners', 'Current Height':'Current Height',
    'Payment Method':'Payment Method', 'Network Mode':'Network Mode', 'Connection':'Connection',
    'Miner URL':'Miner URL', 'Username':'Username', 'Your':'Your', 'payment code, optionally':'payment code, optionally',
    'Password':'Password', 'Pool Wallet':'Pool Wallet', 'Payments':'Payments', 'Run Accounting':'Run Accounting',
    'Mode':'Mode', 'Minimum Payout':'Minimum Payout', 'Pool Fee':'Pool Fee', 'Auto Pay':'Auto Pay',
    'Payout Gate':'Payout Gate', 'Balances':'Balances', 'Wallet':'Wallet', 'Confirmed TKM':'Confirmed TKM',
    'Pending Round TKM':'Pending Round TKM', 'Total TKM':'Total TKM', 'Workers':'Workers', 'Worker':'Worker',
    'Accepted':'Accepted', 'Rejected':'Rejected', 'Round Shares':'Round Shares', 'Last Seen':'Last Seen',
    'Recent Payouts':'Recent Payouts', 'Amount':'Amount', 'Status':'Status', 'Transaction':'Transaction',
    'Created':'Created', 'Previous':'Previous', 'Next':'Next', 'No payouts yet':'No payouts yet',
    'No workers connected':'No workers connected', 'No workers found':'No workers found', 'No balances yet':'No balances yet',
    'loading':'loading', 'enabled':'enabled', 'disabled':'disabled', 'ready':'ready', 'blocked':'blocked',
    'waiting for fork status':'waiting for fork status', 'Wallet balance and payout history':'Wallet balance and payout history',
    'Enter your Shield2 code or 0x payout address':'Enter your Shield2 code or 0x payout address', 'Lookup':'Lookup',
    'Confirmed':'Confirmed', 'Pending Round':'Pending Round', 'Paid':'Paid', 'Shares':'Shares', 'Network':'Network',
    'Pool operations and payout state':'Pool operations and payout state', 'Run Payments':'Run Payments',
    'Pool Wallet Latest':'Pool Wallet Latest', 'Confirmed Spendable':'Confirmed Spendable', 'Miner Balance Owed':'Miner Balance Owed',
    'Redis State':'Redis State', 'Fork Mode':'Fork Mode', 'Payout Configuration':'Payout Configuration',
    'Miner Balances':'Miner Balances', 'Public URL':'Public URL', 'HTTP bind':'HTTP bind', 'Stratum public':'Stratum public',
    'Stratum bind':'Stratum bind', 'Explorer':'Explorer', 'Node RPC':'Node RPC', 'Work method':'Work method',
    'Total shares':'Total shares', 'Uptime seconds':'Uptime seconds', 'online':'online', 'offline':'offline',
    'yes':'yes', 'no':'no', 'Page':'Page', 'of':'of', 'payouts':'payouts', 'payments':'payments',
    'block':'block', 'bytes saved':'bytes saved', 'Legacy':'Legacy', 'Privacy':'Privacy', 'PQ':'PQ',
    'Pool wallet':'Pool wallet', 'Payout status':'Payout status', 'Latest balance':'Latest balance',
    'Confirmed balance':'Confirmed balance', 'Pending balance':'Pending balance', 'Usable balance':'Usable balance',
    'Reserve':'Reserve', 'Spendable':'Spendable', 'Total miner balance owed':'Total miner balance owed',
    'Estimated next tx fee':'Estimated next tx fee', 'Spendable after next fee':'Spendable after next fee',
    'Next payout':'Next payout', 'Payout tx type':'Payout tx type', 'Pool wallet algorithm':'Pool wallet algorithm',
    'Quantum active':'Quantum active', 'Privacy commitments active':'Privacy commitments active',
    'Shielded prover configured':'Shielded prover configured', 'Shielded payouts enabled':'Shielded payouts enabled',
    'Payout gate':'Payout gate', 'Password configured':'Password configured', 'Daemon coinbase':'Daemon coinbase',
    'Rewards go to pool wallet':'Rewards go to pool wallet', 'Connected miners':'Connected miners', 'Redis':'Redis',
    'Auto pay':'Auto pay', 'Payment mode':'Payment mode', 'Block reward':'Block reward', 'Pool fee':'Pool fee',
    'Minimum payout':'Minimum payout', 'Configured maximum per tx':'Configured maximum per tx',
    'Effective maximum per tx':'Effective maximum per tx', 'Payment interval':'Payment interval',
    'Work poll interval':'Work poll interval', 'Confirmations for scheduled pay':'Confirmations for scheduled pay',
    'Shielded payout prover':'Shielded payout prover', 'Shielded payout mode':'Shielded payout mode',
    'Privacy commitment time':'Privacy commitment time', 'Quantum-resistant time':'Quantum-resistant time',
    'Recent payment records':'Recent payment records', 'default':'default', 'pending round':'pending round',
    'at confirmed block':'at confirmed block', 'No payments yet':'No payments yet', 'payout tx type':'payout tx type',
    'shielded prover ready':'shielded prover ready', 'low pool wallet balance':'low pool wallet balance'
  };
  var overrides = {
    zh: {'Language':'语言','RandomX mining · Shield2-ready payouts':'RandomX 挖矿 · Shield2 支付','Miner Lookup':'矿工查询','Admin':'管理','Refresh':'刷新','Dashboard':'控制面板','Pool Shares':'矿池份额','Connected Miners':'已连接矿工','Current Height':'当前高度','Payment Method':'支付方式','Network Mode':'网络模式','Connection':'连接','Miner URL':'矿工 URL','Username':'用户名','Your':'你的','payment code, optionally':'支付代码，可选 .worker','Password':'密码','Pool Wallet':'矿池钱包','Payments':'支付','Run Accounting':'运行结算','Mode':'模式','Minimum Payout':'最低支付','Pool Fee':'矿池费用','Auto Pay':'自动支付','Payout Gate':'支付门槛','Balances':'余额','Wallet':'钱包','Confirmed TKM':'已确认 TKM','Pending Round TKM':'待处理轮次 TKM','Total TKM':'总计 TKM','Workers':'工作线程','Worker':'工作线程','Accepted':'接受','Rejected':'拒绝','Round Shares':'轮次份额','Last Seen':'最后活动','Recent Payouts':'最近支付','Amount':'金额','Status':'状态','Transaction':'交易','Created':'创建时间','Previous':'上一页','Next':'下一页','No payouts yet':'暂无支付','No workers connected':'暂无连接的矿工','No workers found':'未找到工作线程','No balances yet':'暂无余额','loading':'加载中','enabled':'已启用','disabled':'已禁用','ready':'就绪','blocked':'已阻止','waiting for fork status':'等待分叉状态','Wallet balance and payout history':'钱包余额和支付记录','Enter your Shield2 code or 0x payout address':'输入 Shield2 代码或 0x 支付地址','Lookup':'查询','Confirmed':'已确认','Pending Round':'待处理轮次','Paid':'已支付','Shares':'份额','Network':'网络','Pool operations and payout state':'矿池运行和支付状态','Run Payments':'运行支付','Pool Wallet Latest':'矿池钱包最新余额','Confirmed Spendable':'已确认可用','Miner Balance Owed':'应付矿工余额','Redis State':'Redis 状态','Fork Mode':'分叉模式','Payout Configuration':'支付配置','Miner Balances':'矿工余额','Public URL':'公共 URL','HTTP bind':'HTTP 绑定','Stratum public':'Stratum 公共地址','Stratum bind':'Stratum 绑定','Explorer':'浏览器','Node RPC':'节点 RPC','Work method':'工作方法','Total shares':'总份额','Uptime seconds':'运行秒数','online':'在线','offline':'离线','yes':'是','no':'否','Page':'第','of':'共','payouts':'笔支付','payments':'笔支付','block':'区块','bytes saved':'已保存字节','Legacy':'传统','Privacy':'隐私','PQ':'后量子'},
    ru: {'Language':'Язык','Miner Lookup':'Поиск майнера','Admin':'Администратор','Refresh':'Обновить','Dashboard':'Панель','Pool Shares':'Доли пула','Connected Miners':'Подключённые майнеры','Current Height':'Текущая высота','Payment Method':'Метод выплат','Network Mode':'Режим сети','Connection':'Подключение','Miner URL':'URL майнера','Username':'Имя пользователя','Your':'Ваш','payment code, optionally':'код платежа, необязательно','Password':'Пароль','Pool Wallet':'Кошелёк пула','Payments':'Выплаты','Run Accounting':'Рассчитать выплаты','Mode':'Режим','Minimum Payout':'Минимальная выплата','Pool Fee':'Комиссия пула','Auto Pay':'Автовыплата','Payout Gate':'Порог выплаты','Balances':'Балансы','Wallet':'Кошелёк','Confirmed TKM':'Подтверждено TKM','Pending Round TKM':'Текущий раунд TKM','Total TKM':'Всего TKM','Workers':'Воркеры','Worker':'Воркер','Accepted':'Принято','Rejected':'Отклонено','Round Shares':'Доли раунда','Last Seen':'Последняя активность','Recent Payouts':'Последние выплаты','Amount':'Сумма','Status':'Статус','Transaction':'Транзакция','Created':'Создано','Previous':'Назад','Next':'Далее','No payouts yet':'Выплат пока нет','No workers connected':'Нет подключённых воркеров','No workers found':'Воркеры не найдены','No balances yet':'Балансов пока нет','loading':'загрузка','enabled':'включено','disabled':'выключено','ready':'готово','blocked':'заблокировано','waiting for fork status':'ожидание статуса форка','Wallet balance and payout history':'Баланс кошелька и история выплат','Lookup':'Найти','Confirmed':'Подтверждено','Pending Round':'Текущий раунд','Paid':'Выплачено','Shares':'Доли','Network':'Сеть','Pool operations and payout state':'Работа пула и состояние выплат','Run Payments':'Запустить выплаты','Payout Configuration':'Настройки выплат','Miner Balances':'Балансы майнеров','online':'в сети','offline':'не в сети','yes':'да','no':'нет','Page':'Страница','of':'из','payouts':'выплат','payments':'платежей','block':'блок','Legacy':'Обычный','Privacy':'Приватность','PQ':'PQ'},
    ja: {'Language':'言語','Miner Lookup':'マイナー検索','Admin':'管理','Refresh':'更新','Dashboard':'ダッシュボード','Pool Shares':'プールシェア','Connected Miners':'接続中のマイナー','Current Height':'現在の高さ','Payment Method':'支払い方法','Network Mode':'ネットワークモード','Connection':'接続','Miner URL':'マイナー URL','Username':'ユーザー名','Your':'あなたの','payment code, optionally':'支払いコード（任意で .worker）','Password':'パスワード','Pool Wallet':'プールウォレット','Payments':'支払い','Run Accounting':'会計を実行','Mode':'モード','Minimum Payout':'最低支払額','Pool Fee':'プール手数料','Auto Pay':'自動支払い','Payout Gate':'支払い条件','Balances':'残高','Wallet':'ウォレット','Confirmed TKM':'確認済み TKM','Pending Round TKM':'保留中ラウンド TKM','Total TKM':'合計 TKM','Workers':'ワーカー','Worker':'ワーカー','Accepted':'承認','Rejected':'拒否','Round Shares':'ラウンドシェア','Last Seen':'最終確認','Recent Payouts':'最近の支払い','Amount':'金額','Status':'状態','Transaction':'トランザクション','Created':'作成日時','Previous':'前へ','Next':'次へ','No payouts yet':'支払いはまだありません','No workers connected':'接続中のワーカーはありません','No workers found':'ワーカーが見つかりません','No balances yet':'残高はまだありません','loading':'読み込み中','enabled':'有効','disabled':'無効','ready':'準備完了','blocked':'停止中','waiting for fork status':'フォーク状態を待機中','Wallet balance and payout history':'ウォレット残高と支払い履歴','Lookup':'検索','Confirmed':'確認済み','Pending Round':'保留中ラウンド','Paid':'支払済み','Shares':'シェア','Network':'ネットワーク','Pool operations and payout state':'プール運用と支払い状態','Run Payments':'支払いを実行','Payout Configuration':'支払い設定','Miner Balances':'マイナー残高','online':'オンライン','offline':'オフライン','yes':'はい','no':'いいえ','Page':'ページ','of':'/','payouts':'件の支払い','payments':'件の支払い','block':'ブロック','Legacy':'レガシー','Privacy':'プライバシー','PQ':'PQ'},
    ko: {'Language':'언어','Miner Lookup':'채굴자 조회','Admin':'관리자','Refresh':'새로고침','Dashboard':'대시보드','Pool Shares':'풀 지분','Connected Miners':'연결된 채굴자','Current Height':'현재 높이','Payment Method':'지급 방식','Network Mode':'네트워크 모드','Connection':'연결','Miner URL':'채굴 URL','Username':'사용자 이름','Your':'내','payment code, optionally':'지급 코드, 선택적 .worker','Password':'비밀번호','Pool Wallet':'풀 지갑','Payments':'지급','Run Accounting':'정산 실행','Mode':'모드','Minimum Payout':'최소 지급액','Pool Fee':'풀 수수료','Auto Pay':'자동 지급','Payout Gate':'지급 조건','Balances':'잔액','Wallet':'지갑','Confirmed TKM':'확정 TKM','Pending Round TKM':'대기 라운드 TKM','Total TKM':'총 TKM','Workers':'워커','Worker':'워커','Accepted':'승인','Rejected':'거부','Round Shares':'라운드 지분','Last Seen':'최근 확인','Recent Payouts':'최근 지급','Amount':'금액','Status':'상태','Transaction':'거래','Created':'생성됨','Previous':'이전','Next':'다음','No payouts yet':'지급 내역이 없습니다','No workers connected':'연결된 워커가 없습니다','No workers found':'워커를 찾을 수 없습니다','No balances yet':'잔액이 없습니다','loading':'로드 중','enabled':'사용','disabled':'사용 안 함','ready':'준비됨','blocked':'차단됨','waiting for fork status':'포크 상태 대기 중','Wallet balance and payout history':'지갑 잔액 및 지급 내역','Lookup':'조회','Confirmed':'확정','Pending Round':'대기 라운드','Paid':'지급됨','Shares':'지분','Network':'네트워크','Pool operations and payout state':'풀 운영 및 지급 상태','Run Payments':'지급 실행','Payout Configuration':'지급 설정','Miner Balances':'채굴자 잔액','online':'온라인','offline':'오프라인','yes':'예','no':'아니요','Page':'페이지','of':'/','payouts':'지급','payments':'결제','block':'블록','Legacy':'레거시','Privacy':'개인정보 보호','PQ':'PQ'},
    es: {'Language':'Idioma','Miner Lookup':'Consulta de minero','Admin':'Administrador','Refresh':'Actualizar','Dashboard':'Panel','Pool Shares':'Participaciones del pool','Connected Miners':'Mineros conectados','Current Height':'Altura actual','Payment Method':'Método de pago','Network Mode':'Modo de red','Connection':'Conexión','Miner URL':'URL del minero','Username':'Usuario','Your':'Tu','payment code, optionally':'código de pago, opcional .worker','Password':'Contraseña','Pool Wallet':'Billetera del pool','Payments':'Pagos','Run Accounting':'Ejecutar contabilidad','Mode':'Modo','Minimum Payout':'Pago mínimo','Pool Fee':'Comisión del pool','Auto Pay':'Pago automático','Payout Gate':'Condición de pago','Balances':'Saldos','Wallet':'Billetera','Confirmed TKM':'TKM confirmado','Pending Round TKM':'TKM de ronda pendiente','Total TKM':'TKM total','Workers':'Trabajadores','Worker':'Trabajador','Accepted':'Aceptadas','Rejected':'Rechazadas','Round Shares':'Participaciones de ronda','Last Seen':'Última actividad','Recent Payouts':'Pagos recientes','Amount':'Importe','Status':'Estado','Transaction':'Transacción','Created':'Creado','Previous':'Anterior','Next':'Siguiente','No payouts yet':'Aún no hay pagos','No workers connected':'No hay mineros conectados','No workers found':'No se encontraron trabajadores','No balances yet':'Aún no hay saldos','loading':'cargando','enabled':'activado','disabled':'desactivado','ready':'listo','blocked':'bloqueado','waiting for fork status':'esperando el estado del fork','Wallet balance and payout history':'Saldo de billetera e historial de pagos','Lookup':'Consultar','Confirmed':'Confirmado','Pending Round':'Ronda pendiente','Paid':'Pagado','Shares':'Participaciones','Network':'Red','Pool operations and payout state':'Operaciones del pool y estado de pagos','Run Payments':'Ejecutar pagos','Payout Configuration':'Configuración de pagos','Miner Balances':'Saldos de mineros','online':'en línea','offline':'fuera de línea','yes':'sí','no':'no','Page':'Página','of':'de','payouts':'pagos','payments':'pagos','block':'bloque','Legacy':'Clásico','Privacy':'Privacidad','PQ':'PQ'},
    fr: {'Language':'Langue','Miner Lookup':'Recherche de mineur','Admin':'Administration','Refresh':'Actualiser','Dashboard':'Tableau de bord','Pool Shares':'Parts du pool','Connected Miners':'Mineurs connectés','Current Height':'Hauteur actuelle','Payment Method':'Mode de paiement','Network Mode':'Mode réseau','Connection':'Connexion','Miner URL':'URL du mineur','Username':'Nom d’utilisateur','Password':'Mot de passe','Pool Wallet':'Portefeuille du pool','Payments':'Paiements','Run Accounting':'Lancer la comptabilité','Mode':'Mode','Minimum Payout':'Paiement minimum','Pool Fee':'Frais du pool','Auto Pay':'Paiement automatique','Payout Gate':'Seuil de paiement','Balances':'Soldes','Wallet':'Portefeuille','Confirmed TKM':'TKM confirmé','Pending Round TKM':'TKM de la manche en attente','Total TKM':'Total TKM','Workers':'Workers','Accepted':'Acceptées','Rejected':'Rejetées','Round Shares':'Parts de la manche','Last Seen':'Dernière activité','Recent Payouts':'Paiements récents','Amount':'Montant','Status':'État','Transaction':'Transaction','Created':'Créé','Previous':'Précédent','Next':'Suivant','No payouts yet':'Aucun paiement','No workers connected':'Aucun worker connecté','No workers found':'Aucun worker trouvé','No balances yet':'Aucun solde','loading':'chargement','enabled':'activé','disabled':'désactivé','ready':'prêt','blocked':'bloqué','Wallet balance and payout history':'Solde du portefeuille et historique des paiements','Lookup':'Rechercher','Confirmed':'Confirmé','Pending Round':'Manche en attente','Paid':'Payé','Shares':'Parts','Network':'Réseau','Pool operations and payout state':'Opérations du pool et état des paiements','Run Payments':'Lancer les paiements','Payout Configuration':'Configuration des paiements','Miner Balances':'Soldes des mineurs','online':'en ligne','offline':'hors ligne','yes':'oui','no':'non','Page':'Page','of':'sur','payouts':'paiements','payments':'paiements','block':'bloc','Legacy':'Classique','Privacy':'Confidentialité','PQ':'PQ'},
    de: {'Language':'Sprache','Miner Lookup':'Miner suchen','Admin':'Administration','Refresh':'Aktualisieren','Dashboard':'Übersicht','Pool Shares':'Pool-Anteile','Connected Miners':'Verbundene Miner','Current Height':'Aktuelle Höhe','Payment Method':'Zahlungsmethode','Network Mode':'Netzwerkmodus','Connection':'Verbindung','Miner URL':'Miner-URL','Username':'Benutzername','Password':'Passwort','Pool Wallet':'Pool-Wallet','Payments':'Zahlungen','Run Accounting':'Abrechnung ausführen','Mode':'Modus','Minimum Payout':'Mindestzahlung','Pool Fee':'Pool-Gebühr','Auto Pay':'Automatische Zahlung','Payout Gate':'Auszahlungsschwelle','Balances':'Guthaben','Wallet':'Wallet','Confirmed TKM':'Bestätigte TKM','Pending Round TKM':'Offene Runden-TKM','Total TKM':'TKM gesamt','Workers':'Worker','Accepted':'Angenommen','Rejected':'Abgelehnt','Round Shares':'Rundenanteile','Last Seen':'Zuletzt gesehen','Recent Payouts':'Letzte Auszahlungen','Amount':'Betrag','Status':'Status','Transaction':'Transaktion','Created':'Erstellt','Previous':'Zurück','Next':'Weiter','No payouts yet':'Noch keine Auszahlungen','No workers connected':'Keine Worker verbunden','No workers found':'Keine Worker gefunden','No balances yet':'Noch keine Guthaben','loading':'Laden','enabled':'aktiviert','disabled':'deaktiviert','ready':'bereit','blocked':'blockiert','Wallet balance and payout history':'Wallet-Guthaben und Auszahlungshistorie','Lookup':'Suchen','Confirmed':'Bestätigt','Pending Round':'Offene Runde','Paid':'Bezahlt','Shares':'Anteile','Network':'Netzwerk','Pool operations and payout state':'Pool-Betrieb und Auszahlungsstatus','Run Payments':'Zahlungen ausführen','Payout Configuration':'Auszahlungskonfiguration','Miner Balances':'Miner-Guthaben','online':'online','offline':'offline','yes':'ja','no':'nein','Page':'Seite','of':'von','payouts':'Auszahlungen','payments':'Zahlungen','block':'Block','Legacy':'Legacy','Privacy':'Privatsphäre','PQ':'PQ'},
    pt: {'Language':'Idioma','Miner Lookup':'Consultar minerador','Admin':'Administração','Refresh':'Atualizar','Dashboard':'Painel','Pool Shares':'Participações do pool','Connected Miners':'Mineradores conectados','Current Height':'Altura atual','Payment Method':'Método de pagamento','Network Mode':'Modo de rede','Connection':'Conexão','Miner URL':'URL do minerador','Username':'Usuário','Password':'Senha','Pool Wallet':'Carteira do pool','Payments':'Pagamentos','Run Accounting':'Executar contabilidade','Mode':'Modo','Minimum Payout':'Pagamento mínimo','Pool Fee':'Taxa do pool','Auto Pay':'Pagamento automático','Payout Gate':'Limite de pagamento','Balances':'Saldos','Wallet':'Carteira','Confirmed TKM':'TKM confirmado','Pending Round TKM':'TKM da rodada pendente','Total TKM':'TKM total','Workers':'Trabalhadores','Accepted':'Aceitas','Rejected':'Rejeitadas','Round Shares':'Participações da rodada','Last Seen':'Última atividade','Recent Payouts':'Pagamentos recentes','Amount':'Valor','Status':'Status','Transaction':'Transação','Created':'Criado','Previous':'Anterior','Next':'Próximo','No payouts yet':'Ainda não há pagamentos','No workers connected':'Nenhum minerador conectado','No workers found':'Nenhum trabalhador encontrado','No balances yet':'Ainda não há saldos','loading':'carregando','enabled':'ativado','disabled':'desativado','ready':'pronto','blocked':'bloqueado','Wallet balance and payout history':'Saldo da carteira e histórico de pagamentos','Lookup':'Consultar','Confirmed':'Confirmado','Pending Round':'Rodada pendente','Paid':'Pago','Shares':'Participações','Network':'Rede','Pool operations and payout state':'Operações do pool e estado dos pagamentos','Run Payments':'Executar pagamentos','Payout Configuration':'Configuração de pagamentos','Miner Balances':'Saldos dos mineradores','online':'online','offline':'offline','yes':'sim','no':'não','Page':'Página','of':'de','payouts':'pagamentos','payments':'pagamentos','block':'bloco','Legacy':'Legado','Privacy':'Privacidade','PQ':'PQ'},
    ar: {'Language':'اللغة','Miner Lookup':'بحث عن عامل التعدين','Admin':'الإدارة','Refresh':'تحديث','Dashboard':'لوحة التحكم','Pool Shares':'حصص المجمع','Connected Miners':'المعدنون المتصلون','Current Height':'الارتفاع الحالي','Payment Method':'طريقة الدفع','Network Mode':'وضع الشبكة','Connection':'الاتصال','Miner URL':'عنوان عامل التعدين','Username':'اسم المستخدم','Password':'كلمة المرور','Pool Wallet':'محفظة المجمع','Payments':'المدفوعات','Run Accounting':'تشغيل المحاسبة','Mode':'الوضع','Minimum Payout':'الحد الأدنى للدفع','Pool Fee':'رسوم المجمع','Auto Pay':'الدفع التلقائي','Payout Gate':'بوابة الدفع','Balances':'الأرصدة','Wallet':'المحفظة','Confirmed TKM':'TKM مؤكد','Pending Round TKM':'TKM للجولة المعلقة','Total TKM':'إجمالي TKM','Workers':'العاملون','Accepted':'مقبول','Rejected':'مرفوض','Round Shares':'حصص الجولة','Last Seen':'آخر ظهور','Recent Payouts':'المدفوعات الأخيرة','Amount':'المبلغ','Status':'الحالة','Transaction':'المعاملة','Created':'أُنشئ','Previous':'السابق','Next':'التالي','No payouts yet':'لا توجد مدفوعات بعد','No workers connected':'لا يوجد عمال متصلون','No workers found':'لم يتم العثور على عمال','No balances yet':'لا توجد أرصدة بعد','loading':'جار التحميل','enabled':'مفعّل','disabled':'معطّل','ready':'جاهز','blocked':'محظور','Wallet balance and payout history':'رصيد المحفظة وسجل المدفوعات','Lookup':'بحث','Confirmed':'مؤكد','Pending Round':'الجولة المعلقة','Paid':'مدفوع','Shares':'الحصص','Network':'الشبكة','Pool operations and payout state':'تشغيل المجمع وحالة المدفوعات','Run Payments':'تشغيل المدفوعات','Payout Configuration':'إعدادات الدفع','Miner Balances':'أرصدة المعدنين','online':'متصل','offline':'غير متصل','yes':'نعم','no':'لا','Page':'صفحة','of':'من','payouts':'مدفوعات','payments':'مدفوعات','block':'كتلة','Legacy':'تقليدي','Privacy':'خصوصية','PQ':'PQ'}
  };
  var adminLabels = {
    zh: {'Pool wallet':'矿池钱包','Payout status':'支付状态','Latest balance':'最新余额','Confirmed balance':'已确认余额','Pending balance':'待处理余额','Usable balance':'可用余额','Reserve':'储备','Spendable':'可支配','Total miner balance owed':'应付矿工总额','Estimated next tx fee':'预计下笔交易费用','Spendable after next fee':'扣除下笔费用后可用','Next payout':'下一笔支付','Payout tx type':'支付交易类型','Pool wallet algorithm':'矿池钱包算法','Quantum active':'量子安全已启用','Privacy commitments active':'隐私承诺已启用','Shielded prover configured':'已配置隐私证明器','Shielded payouts enabled':'已启用隐私支付','Payout gate':'支付门槛','Password configured':'已配置密码','Daemon coinbase':'节点 Coinbase','Rewards go to pool wallet':'奖励发送到矿池钱包','Connected miners':'已连接矿工','Redis':'Redis','Auto pay':'自动支付','Payment mode':'支付模式','Block reward':'区块奖励','Pool fee':'矿池费用','Minimum payout':'最低支付','Configured maximum per tx':'配置的单笔上限','Effective maximum per tx':'实际单笔上限','Payment interval':'支付间隔','Work poll interval':'工作轮询间隔','Confirmations for scheduled pay':'计划支付确认数','Shielded payout prover':'隐私支付证明器','Shielded payout mode':'隐私支付模式','Privacy commitment time':'隐私承诺时间','Quantum-resistant time':'抗量子时间','Recent payment records':'最近支付记录','default':'默认','pending round':'待处理轮次','at confirmed block':'在已确认区块','No payments yet':'暂无支付','payout tx type':'支付交易类型','shielded prover ready':'隐私证明器就绪','low pool wallet balance':'矿池钱包余额不足'},
    ru: {'Pool wallet':'Кошелёк пула','Payout status':'Статус выплаты','Latest balance':'Последний баланс','Confirmed balance':'Подтверждённый баланс','Pending balance':'Ожидающий баланс','Usable balance':'Доступный баланс','Reserve':'Резерв','Spendable':'Доступно для трат','Total miner balance owed':'Всего начислено майнерам','Estimated next tx fee':'Оценка комиссии следующей транзакции','Spendable after next fee':'Доступно после комиссии','Next payout':'Следующая выплата','Payout tx type':'Тип транзакции выплаты','Pool wallet algorithm':'Алгоритм кошелька пула','Quantum active':'Квантовая защита активна','Privacy commitments active':'Приватные обязательства активны','Shielded prover configured':'Скрытый доказатель настроен','Shielded payouts enabled':'Скрытые выплаты включены','Payout gate':'Порог выплаты','Password configured':'Пароль настроен','Daemon coinbase':'Coinbase демона','Rewards go to pool wallet':'Награды идут в кошелёк пула','Connected miners':'Подключённые майнеры','Redis':'Redis','Auto pay':'Автовыплата','Payment mode':'Режим выплат','Block reward':'Награда за блок','Pool fee':'Комиссия пула','Minimum payout':'Минимальная выплата','Configured maximum per tx':'Настроенный максимум за транзакцию','Effective maximum per tx':'Фактический максимум за транзакцию','Payment interval':'Интервал выплат','Work poll interval':'Интервал опроса работы','Confirmations for scheduled pay':'Подтверждения плановой выплаты','Shielded payout prover':'Доказатель скрытых выплат','Shielded payout mode':'Режим скрытых выплат','Privacy commitment time':'Время приватных обязательств','Quantum-resistant time':'Время квантовой защиты','Recent payment records':'Последние записи платежей','default':'по умолчанию','pending round':'текущий раунд','at confirmed block':'на подтверждённом блоке','No payments yet':'Платежей пока нет','payout tx type':'тип транзакции выплаты','shielded prover ready':'доказатель скрытых выплат готов','low pool wallet balance':'низкий баланс кошелька пула'},
    ja: {'Pool wallet':'プールウォレット','Payout status':'支払い状態','Latest balance':'最新残高','Confirmed balance':'確認済み残高','Pending balance':'保留残高','Usable balance':'利用可能残高','Reserve':'準備金','Spendable':'使用可能','Total miner balance owed':'マイナー未払い合計','Estimated next tx fee':'次の取引手数料の推定','Spendable after next fee':'手数料後の使用可能額','Next payout':'次回支払い','Payout tx type':'支払い取引タイプ','Pool wallet algorithm':'プールウォレットのアルゴリズム','Quantum active':'量子耐性が有効','Privacy commitments active':'プライバシーコミットメントが有効','Shielded prover configured':'シールド証明器を設定済み','Shielded payouts enabled':'シールド支払いを有効化','Payout gate':'支払いゲート','Password configured':'パスワード設定済み','Daemon coinbase':'デーモン Coinbase','Rewards go to pool wallet':'報酬はプールウォレットへ','Connected miners':'接続中のマイナー','Redis':'Redis','Auto pay':'自動支払い','Payment mode':'支払いモード','Block reward':'ブロック報酬','Pool fee':'プール手数料','Minimum payout':'最低支払額','Configured maximum per tx':'設定済み取引上限','Effective maximum per tx':'実効取引上限','Payment interval':'支払い間隔','Work poll interval':'作業ポーリング間隔','Confirmations for scheduled pay':'予定支払いの確認数','Shielded payout prover':'シールド支払い証明器','Shielded payout mode':'シールド支払いモード','Privacy commitment time':'プライバシーコミットメント時刻','Quantum-resistant time':'量子耐性時刻','Recent payment records':'最近の支払い記録','default':'既定','pending round':'保留ラウンド','at confirmed block':'確認済みブロック','No payments yet':'支払いはまだありません','payout tx type':'支払い取引タイプ','shielded prover ready':'シールド証明器準備完了','low pool wallet balance':'プールウォレット残高不足'},
    es: {'Pool wallet':'Billetera del pool','Payout status':'Estado del pago','Latest balance':'Saldo más reciente','Confirmed balance':'Saldo confirmado','Pending balance':'Saldo pendiente','Usable balance':'Saldo utilizable','Reserve':'Reserva','Spendable':'Disponible','Total miner balance owed':'Total adeudado a mineros','Estimated next tx fee':'Comisión estimada de la próxima transacción','Spendable after next fee':'Disponible después de la comisión','Next payout':'Próximo pago','Payout tx type':'Tipo de transacción de pago','Pool wallet algorithm':'Algoritmo de la billetera del pool','Quantum active':'Resistencia cuántica activa','Privacy commitments active':'Compromisos de privacidad activos','Shielded prover configured':'Probador blindado configurado','Shielded payouts enabled':'Pagos blindados activados','Payout gate':'Condición de pago','Password configured':'Contraseña configurada','Daemon coinbase':'Coinbase del daemon','Rewards go to pool wallet':'Las recompensas van a la billetera del pool','Connected miners':'Mineros conectados','Redis':'Redis','Auto pay':'Pago automático','Payment mode':'Modo de pago','Block reward':'Recompensa de bloque','Pool fee':'Comisión del pool','Minimum payout':'Pago mínimo','Configured maximum per tx':'Máximo configurado por transacción','Effective maximum per tx':'Máximo efectivo por transacción','Payment interval':'Intervalo de pago','Work poll interval':'Intervalo de consulta de trabajo','Confirmations for scheduled pay':'Confirmaciones para pagos programados','Shielded payout prover':'Probador de pagos blindados','Shielded payout mode':'Modo de pagos blindados','Privacy commitment time':'Hora del compromiso de privacidad','Quantum-resistant time':'Hora de resistencia cuántica','Recent payment records':'Registros de pagos recientes','default':'predeterminado','pending round':'ronda pendiente','at confirmed block':'en el bloque confirmado','No payments yet':'Aún no hay pagos','payout tx type':'tipo de transacción de pago','shielded prover ready':'probador blindado listo','low pool wallet balance':'saldo bajo de la billetera del pool'}
  };
  var additionalLabels = {
    hi: {'Language':'भाषा','Miner Lookup':'माइनर खोज','Admin':'व्यवस्थापक','Refresh':'रीफ्रेश','Dashboard':'डैशबोर्ड','Pool Shares':'पूल शेयर','Connected Miners':'जुड़े माइनर','Current Height':'वर्तमान ऊंचाई','Payment Method':'भुगतान विधि','Network Mode':'नेटवर्क मोड','Connection':'कनेक्शन','Username':'उपयोगकर्ता नाम','Password':'पासवर्ड','Payments':'भुगतान','Run Accounting':'लेखा चलाएं','Balances':'शेष','Wallet':'वॉलेट','Confirmed TKM':'पुष्ट TKM','Pending Round TKM':'लंबित राउंड TKM','Total TKM':'कुल TKM','Workers':'वर्कर','Accepted':'स्वीकृत','Rejected':'अस्वीकृत','Recent Payouts':'हाल के भुगतान','Amount':'राशि','Status':'स्थिति','Transaction':'लेनदेन','Previous':'पिछला','Next':'अगला','loading':'लोड हो रहा है','enabled':'सक्षम','disabled':'अक्षम','ready':'तैयार','blocked':'अवरुद्ध','online':'ऑनलाइन','offline':'ऑफलाइन','yes':'हां','no':'नहीं','Page':'पृष्ठ','of':'का','Legacy':'विरासत','Privacy':'गोपनीयता','PQ':'PQ'},
    it: {'Language':'Lingua','Miner Lookup':'Cerca miner','Admin':'Amministrazione','Refresh':'Aggiorna','Dashboard':'Dashboard','Pool Shares':'Quote del pool','Connected Miners':'Miner collegati','Current Height':'Altezza attuale','Payment Method':'Metodo di pagamento','Network Mode':'Modalità rete','Connection':'Connessione','Username':'Nome utente','Password':'Password','Payments':'Pagamenti','Run Accounting':'Esegui contabilità','Balances':'Saldi','Wallet':'Portafoglio','Confirmed TKM':'TKM confermati','Pending Round TKM':'TKM del round in attesa','Total TKM':'TKM totali','Workers':'Worker','Accepted':'Accettate','Rejected':'Rifiutate','Recent Payouts':'Pagamenti recenti','Amount':'Importo','Status':'Stato','Transaction':'Transazione','Previous':'Precedente','Next':'Successivo','loading':'caricamento','enabled':'abilitato','disabled':'disabilitato','ready':'pronto','blocked':'bloccato','online':'online','offline':'offline','yes':'sì','no':'no','Page':'Pagina','of':'di','Legacy':'Legacy','Privacy':'Privacy','PQ':'PQ'},
    tr: {'Language':'Dil','Miner Lookup':'Madenci arama','Admin':'Yönetici','Refresh':'Yenile','Dashboard':'Gösterge paneli','Pool Shares':'Havuz payları','Connected Miners':'Bağlı madenciler','Current Height':'Güncel yükseklik','Payment Method':'Ödeme yöntemi','Network Mode':'Ağ modu','Connection':'Bağlantı','Username':'Kullanıcı adı','Password':'Şifre','Payments':'Ödemeler','Run Accounting':'Muhasebeyi çalıştır','Balances':'Bakiyeler','Wallet':'Cüzdan','Confirmed TKM':'Onaylanmış TKM','Pending Round TKM':'Bekleyen tur TKM','Total TKM':'Toplam TKM','Workers':'Çalışanlar','Accepted':'Kabul','Rejected':'Reddedildi','Recent Payouts':'Son ödemeler','Amount':'Tutar','Status':'Durum','Transaction':'İşlem','Previous':'Önceki','Next':'Sonraki','loading':'yükleniyor','enabled':'etkin','disabled':'devre dışı','ready':'hazır','blocked':'engellendi','online':'çevrimiçi','offline':'çevrimdışı','yes':'evet','no':'hayır','Page':'Sayfa','of':'/','Legacy':'Eski','Privacy':'Gizlilik','PQ':'PQ'},
    vi: {'Language':'Ngôn ngữ','Miner Lookup':'Tra cứu máy đào','Admin':'Quản trị','Refresh':'Làm mới','Dashboard':'Bảng điều khiển','Pool Shares':'Cổ phần pool','Connected Miners':'Máy đào đã kết nối','Current Height':'Độ cao hiện tại','Payment Method':'Phương thức thanh toán','Network Mode':'Chế độ mạng','Connection':'Kết nối','Username':'Tên người dùng','Password':'Mật khẩu','Payments':'Thanh toán','Run Accounting':'Chạy đối soát','Balances':'Số dư','Wallet':'Ví','Confirmed TKM':'TKM đã xác nhận','Pending Round TKM':'TKM vòng đang chờ','Total TKM':'Tổng TKM','Workers':'Worker','Accepted':'Đã nhận','Rejected':'Bị từ chối','Recent Payouts':'Thanh toán gần đây','Amount':'Số tiền','Status':'Trạng thái','Transaction':'Giao dịch','Previous':'Trước','Next':'Sau','loading':'đang tải','enabled':'đã bật','disabled':'đã tắt','ready':'sẵn sàng','blocked':'bị chặn','online':'trực tuyến','offline':'ngoại tuyến','yes':'có','no':'không','Page':'Trang','of':'trên','Legacy':'Cũ','Privacy':'Riêng tư','PQ':'PQ'},
    th: {'Language':'ภาษา','Miner Lookup':'ค้นหานักขุด','Admin':'ผู้ดูแล','Refresh':'รีเฟรช','Dashboard':'แดชบอร์ด','Pool Shares':'ส่วนแบ่งพูล','Connected Miners':'นักขุดที่เชื่อมต่อ','Current Height':'ความสูงปัจจุบัน','Payment Method':'วิธีชำระเงิน','Network Mode':'โหมดเครือข่าย','Connection':'การเชื่อมต่อ','Username':'ชื่อผู้ใช้','Password':'รหัสผ่าน','Payments':'การจ่ายเงิน','Run Accounting':'เรียกใช้บัญชี','Balances':'ยอดคงเหลือ','Wallet':'กระเป๋าเงิน','Confirmed TKM':'TKM ยืนยันแล้ว','Pending Round TKM':'TKM รอบที่รอดำเนินการ','Total TKM':'TKM ทั้งหมด','Workers':'เวิร์กเกอร์','Accepted':'ยอมรับ','Rejected':'ปฏิเสธ','Recent Payouts':'การจ่ายล่าสุด','Amount':'จำนวน','Status':'สถานะ','Transaction':'ธุรกรรม','Previous':'ก่อนหน้า','Next':'ถัดไป','loading':'กำลังโหลด','enabled':'เปิดใช้งาน','disabled':'ปิดใช้งาน','ready':'พร้อม','blocked':'ถูกบล็อก','online':'ออนไลน์','offline':'ออฟไลน์','yes':'ใช่','no':'ไม่','Page':'หน้า','of':'จาก','Legacy':'เดิม','Privacy':'ความเป็นส่วนตัว','PQ':'PQ'},
    id: {'Language':'Bahasa','Miner Lookup':'Cari penambang','Admin':'Admin','Refresh':'Muat ulang','Dashboard':'Dasbor','Pool Shares':'Saham pool','Connected Miners':'Penambang terhubung','Current Height':'Ketinggian saat ini','Payment Method':'Metode pembayaran','Network Mode':'Mode jaringan','Connection':'Koneksi','Username':'Nama pengguna','Password':'Kata sandi','Payments':'Pembayaran','Run Accounting':'Jalankan akuntansi','Balances':'Saldo','Wallet':'Dompet','Confirmed TKM':'TKM terkonfirmasi','Pending Round TKM':'TKM ronde tertunda','Total TKM':'Total TKM','Workers':'Pekerja','Accepted':'Diterima','Rejected':'Ditolak','Recent Payouts':'Pembayaran terbaru','Amount':'Jumlah','Status':'Status','Transaction':'Transaksi','Previous':'Sebelumnya','Next':'Berikutnya','loading':'memuat','enabled':'aktif','disabled':'nonaktif','ready':'siap','blocked':'diblokir','online':'online','offline':'offline','yes':'ya','no':'tidak','Page':'Halaman','of':'dari','Legacy':'Lama','Privacy':'Privasi','PQ':'PQ'},
    pl: {'Language':'Język','Miner Lookup':'Wyszukaj górnika','Admin':'Administrator','Refresh':'Odśwież','Dashboard':'Panel','Pool Shares':'Udziały puli','Connected Miners':'Połączeni górnicy','Current Height':'Bieżąca wysokość','Payment Method':'Metoda płatności','Network Mode':'Tryb sieci','Connection':'Połączenie','Username':'Nazwa użytkownika','Password':'Hasło','Payments':'Płatności','Run Accounting':'Uruchom rozliczenie','Balances':'Salda','Wallet':'Portfel','Confirmed TKM':'Potwierdzone TKM','Pending Round TKM':'Oczekujące TKM rundy','Total TKM':'Łącznie TKM','Workers':'Pracownicy','Accepted':'Zaakceptowane','Rejected':'Odrzucone','Recent Payouts':'Ostatnie wypłaty','Amount':'Kwota','Status':'Status','Transaction':'Transakcja','Previous':'Poprzednia','Next':'Następna','loading':'ładowanie','enabled':'włączone','disabled':'wyłączone','ready':'gotowe','blocked':'zablokowane','online':'online','offline':'offline','yes':'tak','no':'nie','Page':'Strona','of':'z','Legacy':'Starsze','Privacy':'Prywatność','PQ':'PQ'},
    nl: {'Language':'Taal','Miner Lookup':'Miner zoeken','Admin':'Beheer','Refresh':'Vernieuwen','Dashboard':'Dashboard','Pool Shares':'Poolaandelen','Connected Miners':'Verbonden miners','Current Height':'Huidige hoogte','Payment Method':'Betaalmethode','Network Mode':'Netwerkmodus','Connection':'Verbinding','Username':'Gebruikersnaam','Password':'Wachtwoord','Payments':'Betalingen','Run Accounting':'Boekhouding uitvoeren','Balances':'Saldi','Wallet':'Portemonnee','Confirmed TKM':'Bevestigde TKM','Pending Round TKM':'Openstaande ronde TKM','Total TKM':'Totale TKM','Workers':'Workers','Accepted':'Geaccepteerd','Rejected':'Afgewezen','Recent Payouts':'Recente betalingen','Amount':'Bedrag','Status':'Status','Transaction':'Transactie','Previous':'Vorige','Next':'Volgende','loading':'laden','enabled':'ingeschakeld','disabled':'uitgeschakeld','ready':'gereed','blocked':'geblokkeerd','online':'online','offline':'offline','yes':'ja','no':'nee','Page':'Pagina','of':'van','Legacy':'Legacy','Privacy':'Privacy','PQ':'PQ'},
    uk: {'Language':'Мова','Miner Lookup':'Пошук майнера','Admin':'Адміністратор','Refresh':'Оновити','Dashboard':'Панель','Pool Shares':'Частки пулу','Connected Miners':'Підключені майнери','Current Height':'Поточна висота','Payment Method':'Метод виплат','Network Mode':'Режим мережі','Connection':'Підключення','Username':'Ім’я користувача','Password':'Пароль','Payments':'Виплати','Run Accounting':'Запустити облік','Balances':'Баланси','Wallet':'Гаманець','Confirmed TKM':'Підтверджено TKM','Pending Round TKM':'TKM поточного раунду','Total TKM':'Усього TKM','Workers':'Воркери','Accepted':'Прийнято','Rejected':'Відхилено','Recent Payouts':'Останні виплати','Amount':'Сума','Status':'Статус','Transaction':'Транзакція','Previous':'Назад','Next':'Далі','loading':'завантаження','enabled':'увімкнено','disabled':'вимкнено','ready':'готово','blocked':'заблоковано','online':'онлайн','offline':'офлайн','yes':'так','no':'ні','Page':'Сторінка','of':'з','Legacy':'Застарілий','Privacy':'Приватність','PQ':'PQ'},
    sw: {'Language':'Lugha','Miner Lookup':'Tafuta mchimbaji','Admin':'Msimamizi','Refresh':'Onyesha upya','Dashboard':'Dashibodi','Pool Shares':'Hisa za pool','Connected Miners':'Wachimbaji waliounganishwa','Current Height':'Urefu wa sasa','Payment Method':'Njia ya malipo','Network Mode':'Hali ya mtandao','Connection':'Muunganisho','Username':'Jina la mtumiaji','Password':'Nenosiri','Payments':'Malipo','Run Accounting':'Endesha uhasibu','Balances':'Salio','Wallet':'Mkoba','Confirmed TKM':'TKM iliyothibitishwa','Pending Round TKM':'TKM ya raundi inayosubiri','Total TKM':'Jumla ya TKM','Workers':'Wafanyakazi','Accepted':'Imekubaliwa','Rejected':'Imekataliwa','Recent Payouts':'Malipo ya hivi karibuni','Amount':'Kiasi','Status':'Hali','Transaction':'Muamala','Previous':'Iliyotangulia','Next':'Inayofuata','loading':'inapakia','enabled':'imewezeshwa','disabled':'imezimwa','ready':'tayari','blocked':'imezuiwa','online':'mtandaoni','offline':'nje ya mtandao','yes':'ndiyo','no':'hapana','Page':'Ukurasa','of':'ya','Legacy':'Urithi','Privacy':'Faragha','PQ':'PQ'}
  };
  Object.keys(additionalLabels).forEach(function (locale) { overrides[locale] = additionalLabels[locale]; });
  Object.keys(adminLabels).forEach(function (locale) { Object.assign(overrides[locale], adminLabels[locale]); });
  var dictionaries = {};
  Object.keys(overrides).forEach(function (locale) { dictionaries[locale] = Object.assign({}, base, overrides[locale]); });
  dictionaries.en = base;
  var locale = 'en';
  try { locale = localStorage.getItem(storageKey) || 'en'; } catch (_) {}
  if (!dictionaries[locale]) locale = 'en';
  var originals = new WeakMap();
  var attributeOriginals = new WeakMap();
  var originalTitle = document.title;
  var applying = false;
  var scheduled = false;

  function mapFor() { return dictionaries[locale] || base; }
  function escapeRegExp(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function translateValue(value) {
    if (!value || !value.trim()) return value;
    var map = mapFor();
    var source = value;
    var exact = map[source.trim()];
    if (exact && source.trim() === source) return exact;
    var result = source;
    Object.keys(map).filter(function (key) { return map[key] !== key && key.length > 2; }).sort(function (a, b) { return b.length - a.length; }).forEach(function (key) {
      var pattern = new RegExp('(^|[^A-Za-z0-9_])' + escapeRegExp(key) + '(?=[^A-Za-z0-9_]|$)', 'g');
      result = result.replace(pattern, function (_, prefix) { return prefix + map[key]; });
    });
    return result;
  }
  function shouldSkip(node) {
    var parent = node.parentElement;
    if (!parent || parent.closest('.tkm-language-picker')) return true;
    return /^(SCRIPT|STYLE|CODE|TEXTAREA|INPUT|SELECT|OPTION)$/i.test(parent.tagName);
  }
  function applyTranslations() {
    if (applying || !document.body) return;
    applying = true;
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(function (node) {
      if (shouldSkip(node)) return;
      if (!originals.has(node)) originals.set(node, node.nodeValue);
      var translated = translateValue(originals.get(node));
      if (node.nodeValue !== translated) node.nodeValue = translated;
    });
    document.querySelectorAll('input[placeholder]').forEach(function (input) {
      if (!attributeOriginals.has(input)) attributeOriginals.set(input, input.getAttribute('placeholder'));
      var placeholder = translateValue(attributeOriginals.get(input));
      if (input.getAttribute('placeholder') !== placeholder) input.setAttribute('placeholder', placeholder);
    });
    var label = document.querySelector('.tkm-language-picker-label');
    if (label && label.textContent !== (mapFor().Language || 'Language')) label.textContent = mapFor().Language || 'Language';
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === 'ar' ? 'rtl' : 'ltr';
    document.title = translateValue(originalTitle);
    applying = false;
  }
  var scheduleFrame = window.requestAnimationFrame || function (callback) { return window.setTimeout(callback, 0); };
  function scheduleApply() {
    if (scheduled) return;
    scheduled = true;
    scheduleFrame(function () { scheduled = false; applyTranslations(); });
  }
  function buildPicker() {
    var header = document.querySelector('header');
    if (!header || document.querySelector('.tkm-language-picker')) return;
    var picker = document.createElement('label');
    picker.className = 'tkm-language-picker';
    picker.innerHTML = '<span class="tkm-language-picker-label">Language</span><select aria-label="Language"></select>';
    var select = picker.querySelector('select');
    languages.forEach(function (item) {
      var option = document.createElement('option');
      option.value = item[0]; option.textContent = item[1]; option.selected = item[0] === locale;
      select.appendChild(option);
    });
    select.addEventListener('change', function () {
      locale = select.value;
      try { localStorage.setItem(storageKey, locale); } catch (_) {}
      applyTranslations();
    });
    var row = header.querySelector('.row');
    if (row) row.insertBefore(picker, row.firstChild);
    else header.appendChild(picker);
    var style = document.createElement('style');
    style.textContent = '.tkm-language-picker{position:relative;z-index:2;display:inline-flex;align-items:center;gap:7px;color:#d8e7fa;font-size:12px;font-weight:700;letter-spacing:.02em}.tkm-language-picker select{appearance:auto;border:1px solid rgba(149,193,255,.45);border-radius:7px;background:#102b4b;color:#f5f9ff;padding:7px 9px;font:inherit;cursor:pointer}.tkm-language-picker select:focus{outline:2px solid rgba(101,168,255,.55);outline-offset:2px}@media(max-width:460px){.tkm-language-picker{width:100%;justify-content:space-between}.tkm-language-picker select{flex:1}}';
    document.head.appendChild(style);
  }
  buildPicker();
  applyTranslations();
  if (window.MutationObserver) new MutationObserver(scheduleApply).observe(document.body, { childList: true, subtree: true, characterData: true });
  window.tkmPoolTranslate = function (nextLocale) {
    if (!dictionaries[nextLocale]) return false;
    locale = nextLocale; applyTranslations(); return true;
  };
}());
</script>`

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{POOL_NAME}}</title>
  <style>
    :root { color-scheme: light; --bg:#f7f8fb; --ink:#141821; --muted:#5b6472; --line:#d9dee7; --panel:#ffffff; --green:#12805c; --red:#b42318; --orange:#9a5b00; --blue:#1b5fc1; }
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
    button, a.button { border:1px solid #0f4ea8; background:var(--blue); color:white; border-radius:6px; padding:9px 12px; font-weight:700; cursor:pointer; text-decoration:none; display:inline-block; }
    button:disabled { opacity:.55; cursor:wait; }
    .ok { color:var(--green); font-weight:700; }
    .bad { color:var(--red); font-weight:700; }
    .warn { color:var(--orange); font-weight:700; }
    .muted { color:var(--muted); }
    .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .pager { display:flex; align-items:center; justify-content:flex-end; gap:10px; margin-top:12px; flex-wrap:wrap; }
    @media (max-width: 860px) { .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } main { padding:16px; } }
    @media (max-width: 560px) { .grid { grid-template-columns:1fr; } header { padding:18px; } .value { font-size:20px; } }
    /* Pool console visual system */
    :root { color-scheme:dark; --bg:#07111f; --ink:#e6edf7; --muted:#93a4ba; --line:rgba(148,163,184,.18); --panel:rgba(14,27,47,.88); --green:#34d399; --red:#fb7185; --orange:#fbbf24; --blue:#65a8ff; }
    body { min-height:100vh; background:radial-gradient(900px 540px at 8% -12%,rgba(29,116,255,.25),transparent 65%),radial-gradient(900px 500px at 100% 0,rgba(16,185,129,.12),transparent 62%),var(--bg); letter-spacing:.01em; }
    header { position:relative; overflow:hidden; background:linear-gradient(115deg,#09162b,#112a4a 52%,#0c2039); border-bottom:1px solid rgba(148,163,184,.18); padding:28px clamp(20px,5vw,56px); }
    header:after { content:""; position:absolute; width:340px; height:340px; right:-120px; top:-220px; border:1px solid rgba(101,168,255,.25); border-radius:50%; box-shadow:0 0 0 42px rgba(101,168,255,.04),0 0 0 84px rgba(101,168,255,.03); }
    header > * { position:relative; z-index:1; } h1 { font-size:clamp(24px,3vw,34px); font-weight:780; letter-spacing:-.04em; } main { max-width:1320px; padding:32px 24px 56px; }
    .grid { gap:16px; grid-template-columns:repeat(5,minmax(0,1fr)); } .panel { background:linear-gradient(145deg,rgba(20,38,65,.96),rgba(10,23,42,.92)); border-color:var(--line); border-radius:14px; box-shadow:0 14px 38px rgba(0,0,0,.18); }
    .metric { min-height:120px; position:relative; overflow:hidden; } .metric:before { content:""; position:absolute; inset:0 auto 0 0; width:3px; background:linear-gradient(#65a8ff,#34d399); } .label { color:#8fa8c8; letter-spacing:.09em; } .value { font-size:clamp(21px,2.2vw,30px); color:#f5f9ff; letter-spacing:-.035em; }
    .section { margin-top:22px; } .section h2 { font-size:18px; letter-spacing:-.02em; } .muted { color:var(--muted); } code { background:rgba(101,168,255,.1); border-color:rgba(101,168,255,.22); color:#bcd7ff; }
    button,a.button { border:1px solid rgba(149,193,255,.45); background:linear-gradient(135deg,#3478dc,#2260bd); border-radius:9px; box-shadow:0 6px 18px rgba(32,96,189,.23); transition:transform .16s ease,filter .16s ease; } button:hover,a.button:hover { transform:translateY(-1px); filter:brightness(1.12); } button:focus-visible,a.button:focus-visible { outline:3px solid rgba(101,168,255,.45); outline-offset:2px; }
    .ok,.bad,.warn { display:inline-flex; align-items:center; gap:5px; padding:3px 8px; border-radius:999px; font-size:12px; } .ok { color:#6ee7b7; background:rgba(52,211,153,.12); } .bad { color:#fda4af; background:rgba(251,113,133,.12); } .warn { color:#fde68a; background:rgba(251,191,36,.12); }
    th { color:#89a3c4; background:rgba(5,15,30,.23); } th,td { border-color:var(--line); padding:12px 10px; } tr:last-child td { border-bottom:0; } table { font-size:13px; } td:first-child { color:#d7e4f7; } a { color:#8bbdff; } .pager { border-top:1px solid var(--line); padding-top:14px; }
    @media(max-width:1050px) { .grid { grid-template-columns:repeat(3,minmax(0,1fr)); } } @media(max-width:700px) { main { padding:20px 14px 40px; } .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .panel { border-radius:12px; padding:14px; } table { display:block; overflow-x:auto; white-space:nowrap; } } @media(max-width:460px) { .grid { grid-template-columns:1fr; } header .row { width:100%; } header .button,header button { flex:1; text-align:center; } }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{{POOL_NAME}}</h1>
      <div class="muted">RandomX mining · Shield2-ready payouts</div>
    </div>
    <div class="row">
      <span>Stratum <code id="stratum">loading</code></span>
      <a class="button" href="/user.html">Miner Lookup</a>
      <a class="button" href="/admin.html">Admin</a>
      <button id="refresh">Refresh</button>
    </div>
  </header>
  <main>
    <div class="grid">
      <div class="panel metric"><div class="label">Pool Shares</div><div class="value" id="shares">0</div></div>
      <div class="panel metric"><div class="label">Connected Miners</div><div class="value" id="workers">0</div></div>
      <div class="panel metric"><div class="label">Current Height</div><div class="value" id="height">0</div></div>
      <div class="panel metric"><div class="label">Payment Method</div><div class="value" id="payment">PROP</div></div>
      <div class="panel metric"><div class="label">Network Mode</div><div class="value" id="networkMode">loading</div></div>
    </div>

    <section class="section panel">
      <h2>Connection</h2>
      <table>
        <tbody>
          <tr><th>Miner URL</th><td><code id="minerUrl"></code></td></tr>
          <tr><th>Username</th><td>Your <code>tkmshield2</code> payment code, optionally <code>.worker</code></td></tr>
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
          <tr><th>Payout Gate</th><td id="payoutGate"></td></tr>
        </tbody>
      </table>
      <h2 style="margin-top:18px">Balances</h2>
      <table><thead><tr><th>Wallet</th><th>Confirmed TKM</th><th>Pending Round TKM</th><th>Total TKM</th></tr></thead><tbody id="balances"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Workers</h2>
      <table><thead><tr><th>Wallet</th><th>Worker</th><th>Accepted</th><th>Rejected</th><th>Round Shares</th><th>Last Seen</th></tr></thead><tbody id="miners"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Recent Payouts</h2>
      <table><thead><tr><th>Wallet</th><th>Amount</th><th>Status</th><th>Transaction</th></tr></thead><tbody id="payments"></tbody></table>
      <div class="pager"><button id="paymentsPrev">Previous</button><span id="paymentsPage" class="muted">Page 1 of 1</span><button id="paymentsNext">Next</button></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const paymentsPageSize = 25;
    let paymentsPage = 0;
    let paymentsRows = [];
    function row(cells) { return '<tr>' + cells.map(v => '<td>' + String(v ?? '') + '</td>').join('') + '</tr>'; }
    const money = (v) => (Number(v || 0)).toFixed(8) + ' TKM';
    function txLink(hash) { return hash && explorerURL ? '<a href="' + explorerURL + '/tx/' + hash + '" target="_blank" rel="noopener">' + hash + '</a>' : (hash || '-'); }
    function networkText(n) {
      const parts = [];
      if (n && n.quantumResistantActive) parts.push('PQ');
      if (n && n.privacyCommitmentActive) parts.push('Privacy');
      return parts.length ? parts.join(' + ') : 'Legacy';
    }
    function networkHTML(n) {
      if (!n) return 'loading';
      return '<span class="' + (n.payoutReady ? 'ok' : 'warn') + '">' + networkText(n) + '</span>';
    }
    let explorerURL = '';
    function renderPayments() {
      const totalPages = Math.max(1, Math.ceil(paymentsRows.length / paymentsPageSize));
      paymentsPage = Math.min(Math.max(0, paymentsPage), totalPages - 1);
      const start = paymentsPage * paymentsPageSize;
      const visible = paymentsRows.slice(start, start + paymentsPageSize);
      $('payments').innerHTML = visible.map(p => row([p.wallet, money(p.amountAntd), p.status, txLink(p.txHash)])).join('') || row(['No payouts yet', '', '', '']);
      $('paymentsPage').textContent = 'Page ' + (paymentsPage + 1) + ' of ' + totalPages + ' (' + paymentsRows.length + ' payouts)';
      $('paymentsPrev').disabled = paymentsPage <= 0;
      $('paymentsNext').disabled = paymentsPage >= totalPages - 1;
    }
    async function load() {
      const res = await fetch('/api/status');
      const s = await res.json();
      $('shares').textContent = s.totalShares;
      $('workers').textContent = (s.authorizedSessions ?? s.connectedSessions ?? s.miners.length);
      $('height').textContent = s.work.height || 0;
      $('payment').textContent = s.paymentMode;
      $('networkMode').innerHTML = networkHTML(s.network);
      $('stratum').textContent = s.stratum;
      $('minerUrl').textContent = 'stratum+tcp://' + s.stratum;
      $('poolWallet').textContent = s.poolWallet;
      explorerURL = s.explorerURL || '';
      $('payMode').textContent = s.paymentMode + ' proportional accepted-share accounting';
      $('minPayout').textContent = s.minPayoutAntd + ' TKM';
      $('fee').textContent = s.feePercent + '%';
      $('autoPay').innerHTML = s.autoPay ? '<span class="ok">enabled</span>' : '<span class="bad">disabled</span>';
      $('payoutGate').innerHTML = s.network && s.network.payoutReady ? '<span class="ok">ready</span>' : '<span class="warn">' + ((s.network && s.network.payoutBlockedReason) || 'waiting for fork status') + '</span>';
      $('miners').innerHTML = s.miners.map(m => row([m.wallet, m.worker || '-', m.acceptedShares, m.rejectedShares, m.roundShares || 0, new Date(m.lastSeen).toLocaleString()])).join('') || row(['No workers connected', '', '', '', '', '']);
      const wallets = Array.from(new Set([...Object.keys(s.balances || {}), ...Object.keys(s.pendingBalances || {})]));
      document.getElementById("balances").innerHTML = wallets.map(w => row([w, money((s.balances || {})[w] || 0), money((s.pendingBalances || {})[w] || 0), money(((s.balances || {})[w] || 0) + ((s.pendingBalances || {})[w] || 0))])).join("") || row(["No balances yet", money(0), money(0), money(0)]);
      paymentsRows = (s.payments || []).slice().reverse();
      renderPayments();
    }
    $('paymentsPrev').onclick = () => { paymentsPage--; renderPayments(); };
    $('paymentsNext').onclick = () => { paymentsPage++; renderPayments(); };
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

const userHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{POOL_NAME}} Miner</title>
  <style>
    :root { color-scheme: light; --bg:#f6f8fb; --ink:#141821; --muted:#5b6472; --line:#d8dee8; --panel:#fff; --green:#12715b; --red:#b42318; --orange:#9a5b00; --blue:#174ea6; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; }
    header { background:#151922; color:#fff; padding:20px 28px; display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap; }
    h1 { margin:0; font-size:24px; letter-spacing:0; }
    main { max-width:1120px; margin:0 auto; padding:24px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; margin-top:16px; }
    .grid { display:grid; gap:14px; grid-template-columns:repeat(4, minmax(0, 1fr)); }
    .metric { min-height:104px; }
    .label { color:var(--muted); font-size:12px; text-transform:uppercase; font-weight:750; }
    .value { margin-top:8px; font-size:24px; font-weight:780; overflow-wrap:anywhere; }
    .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .pager { display:flex; align-items:center; justify-content:flex-end; gap:10px; margin-top:12px; flex-wrap:wrap; }
    input { flex:1 1 360px; min-width:240px; border:1px solid var(--line); border-radius:6px; padding:10px 12px; font:inherit; }
    button, a.button { border:1px solid #0f4ea8; background:var(--blue); color:white; border-radius:6px; padding:10px 12px; font-weight:700; cursor:pointer; text-decoration:none; display:inline-block; }
    table { width:100%; border-collapse:collapse; }
    th, td { padding:9px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; }
    .muted { color:var(--muted); }
    .ok { color:var(--green); font-weight:750; }
    .bad { color:var(--red); font-weight:750; }
    .warn { color:var(--orange); font-weight:750; }
    @media (max-width: 820px) { .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } main { padding:16px; } }
    @media (max-width: 540px) { .grid { grid-template-columns:1fr; } }
    :root { color-scheme:dark; --bg:#07111f; --ink:#e6edf7; --muted:#93a4ba; --line:rgba(148,163,184,.18); --panel:rgba(14,27,47,.88); --green:#34d399; --red:#fb7185; --orange:#fbbf24; --blue:#65a8ff; }
    body { min-height:100vh; background:radial-gradient(800px 500px at 7% -10%,rgba(29,116,255,.25),transparent 65%),var(--bg); } header { background:linear-gradient(115deg,#09162b,#112a4a); border-bottom:1px solid var(--line); padding:28px clamp(20px,5vw,56px); } h1 { font-size:clamp(24px,3vw,34px); letter-spacing:-.04em; } main { max-width:1220px; padding:32px 24px 56px; }
    .panel { background:linear-gradient(145deg,rgba(20,38,65,.96),rgba(10,23,42,.92)); border-color:var(--line); border-radius:14px; box-shadow:0 14px 38px rgba(0,0,0,.18); } .grid { gap:16px; grid-template-columns:repeat(5,minmax(0,1fr)); } .metric { position:relative; overflow:hidden; } .metric:before { content:""; position:absolute; inset:0 auto 0 0; width:3px; background:linear-gradient(#65a8ff,#34d399); } .label { color:#8fa8c8; letter-spacing:.09em; } .value { color:#f5f9ff; letter-spacing:-.035em; }
    input { background:rgba(5,15,30,.48); border-color:rgba(101,168,255,.3); color:var(--ink); border-radius:9px; padding:12px 14px; } input:focus { outline:3px solid rgba(101,168,255,.25); border-color:#65a8ff; } button,a.button { border-color:rgba(149,193,255,.45); background:linear-gradient(135deg,#3478dc,#2260bd); border-radius:9px; box-shadow:0 6px 18px rgba(32,96,189,.23); } .ok,.bad,.warn { display:inline-flex; padding:3px 8px; border-radius:999px; font-size:12px; } .ok { color:#6ee7b7; background:rgba(52,211,153,.12); } .bad { color:#fda4af; background:rgba(251,113,133,.12); } .warn { color:#fde68a; background:rgba(251,191,36,.12); } th,td { border-color:var(--line); padding:12px 10px; } th { color:#89a3c4; background:rgba(5,15,30,.23); } a { color:#8bbdff; } @media(max-width:980px) { .grid { grid-template-columns:repeat(3,minmax(0,1fr)); } } @media(max-width:700px) { main { padding:20px 14px 40px; } .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } table { display:block; overflow-x:auto; white-space:nowrap; } } @media(max-width:460px) { .grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <header>
    <div><h1>{{POOL_NAME}} Miner</h1><div class="muted">Wallet balance and payout history</div></div>
    <div class="row"><a class="button" href="/">Dashboard</a></div>
  </header>
  <main>
    <section class="panel">
      <div class="row">
        <input id="address" placeholder="Enter your Shield2 code or 0x payout address">
        <button id="lookup">Lookup</button>
      </div>
      <div id="error" class="bad" style="margin-top:10px"></div>
    </section>
    <div class="grid">
      <div class="panel metric"><div class="label">Confirmed</div><div class="value" id="confirmed">0</div></div>
      <div class="panel metric"><div class="label">Pending Round</div><div class="value" id="pending">0</div></div>
      <div class="panel metric"><div class="label">Paid</div><div class="value" id="paid">0</div></div>
      <div class="panel metric"><div class="label">Shares</div><div class="value" id="shares">0</div></div>
      <div class="panel metric"><div class="label">Network</div><div class="value" id="networkMode">loading</div></div>
    </div>
    <section class="panel">
      <h2>Workers</h2>
      <table><thead><tr><th>Worker</th><th>Accepted</th><th>Rejected</th><th>Round Shares</th><th>Last Seen</th></tr></thead><tbody id="workers"></tbody></table>
    </section>
    <section class="panel">
      <h2>Payments</h2>
      <table><thead><tr><th>Amount</th><th>Status</th><th>Transaction</th><th>Created</th></tr></thead><tbody id="payments"></tbody></table>
      <div class="pager"><button id="paymentsPrev">Previous</button><span id="paymentsPage" class="muted">Page 1 of 1</span><button id="paymentsNext">Next</button></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const money = (v) => (Number(v || 0)).toFixed(8) + ' TKM';
    const paymentsPageSize = 25;
    let paymentsPage = 0;
    let paymentsRows = [];
    function row(cells) { return '<tr>' + cells.map(v => '<td>' + String(v ?? '') + '</td>').join('') + '</tr>'; }
    function txLink(hash) { return hash && explorerURL ? '<a href="' + explorerURL + '/tx/' + hash + '" target="_blank" rel="noopener">' + hash + '</a>' : (hash || '-'); }
    function networkText(n) {
      const parts = [];
      if (n && n.quantumResistantActive) parts.push('PQ');
      if (n && n.privacyCommitmentActive) parts.push('Privacy');
      return parts.length ? parts.join(' + ') : 'Legacy';
    }
    function networkHTML(n) {
      if (!n) return 'loading';
      return '<span class="' + (n.payoutReady ? 'ok' : 'warn') + '">' + networkText(n) + '</span>';
    }
    let explorerURL = '';
    function renderPayments() {
      const totalPages = Math.max(1, Math.ceil(paymentsRows.length / paymentsPageSize));
      paymentsPage = Math.min(Math.max(0, paymentsPage), totalPages - 1);
      const start = paymentsPage * paymentsPageSize;
      const visible = paymentsRows.slice(start, start + paymentsPageSize);
      $('payments').innerHTML = visible.map(p => row([money(p.amountAntd), p.status, txLink(p.txHash), new Date(p.createdAt).toLocaleString()])).join('') || row(['No payments yet', '', '', '']);
      $('paymentsPage').textContent = 'Page ' + (paymentsPage + 1) + ' of ' + totalPages + ' (' + paymentsRows.length + ' payments)';
      $('paymentsPrev').disabled = paymentsPage <= 0;
      $('paymentsNext').disabled = paymentsPage >= totalPages - 1;
    }
    function setAddress(value) {
      const url = new URL(location.href);
      if (value) url.searchParams.set('address', value); else url.searchParams.delete('address');
      history.replaceState(null, '', url.toString());
    }
    async function load() {
      const address = $('address').value.trim();
      $('error').textContent = '';
      if (!address) return;
      setAddress(address);
      const res = await fetch('/api/user/status?address=' + encodeURIComponent(address));
      if (!res.ok) { $('error').textContent = await res.text(); return; }
      const s = await res.json();
      explorerURL = s.explorerURL || '';
      $('confirmed').textContent = money(s.confirmedBalance);
      $('pending').textContent = money(s.pendingRoundBalance);
      $('paid').textContent = money(s.totalPaid);
      $('shares').textContent = String((s.acceptedShares || 0) + ' / ' + (s.rejectedShares || 0));
      $('networkMode').innerHTML = networkHTML(s.network);
      $('workers').innerHTML = (s.workers || []).map(w => row([w.worker || '-', w.acceptedShares, w.rejectedShares, w.roundShares || 0, new Date(w.lastSeen).toLocaleString()])).join('') || row(['No workers found', '', '', '', '']);
      paymentsRows = (s.payments || []).slice().reverse();
      renderPayments();
    }
    $('paymentsPrev').onclick = () => { paymentsPage--; renderPayments(); };
    $('paymentsNext').onclick = () => { paymentsPage++; renderPayments(); };
    $('lookup').onclick = () => { paymentsPage = 0; load(); };
    $('address').addEventListener('keydown', e => { if (e.key === 'Enter') { paymentsPage = 0; load(); } });
    const initial = new URLSearchParams(location.search).get('address') || '';
    if (initial) { $('address').value = initial; load(); }
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
    :root { color-scheme: light; --bg:#f5f7fb; --ink:#141821; --muted:#5b6472; --line:#d8dee8; --panel:#fff; --green:#12715b; --red:#b42318; --orange:#9a5b00; --blue:#174ea6; }
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
    .warn { color:var(--orange); font-weight:750; }
    .muted { color:var(--muted); }
    .row { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .pager { display:flex; align-items:center; justify-content:flex-end; gap:10px; margin-top:12px; flex-wrap:wrap; }
    .split { display:grid; gap:14px; grid-template-columns:1fr 1fr; }
    @media (max-width: 920px) { .grid { grid-template-columns:repeat(2, minmax(0, 1fr)); } .split { grid-template-columns:1fr; } main { padding:16px; } }
    @media (max-width: 560px) { .grid { grid-template-columns:1fr; } header { padding:18px; } .value { font-size:20px; } }
    :root { color-scheme:dark; --bg:#07111f; --ink:#e6edf7; --muted:#93a4ba; --line:rgba(148,163,184,.18); --panel:rgba(14,27,47,.88); --green:#34d399; --red:#fb7185; --orange:#fbbf24; --blue:#65a8ff; }
    body { min-height:100vh; background:radial-gradient(900px 540px at 8% -12%,rgba(29,116,255,.24),transparent 65%),radial-gradient(800px 460px at 100% 0,rgba(16,185,129,.1),transparent 62%),var(--bg); } header { background:linear-gradient(115deg,#09162b,#112a4a 52%,#0c2039); border-bottom:1px solid var(--line); padding:28px clamp(20px,5vw,56px); } h1 { font-size:clamp(24px,3vw,34px); letter-spacing:-.04em; } main { max-width:1380px; padding:32px 24px 56px; }
    .grid { gap:16px; grid-template-columns:repeat(5,minmax(0,1fr)); } .panel { background:linear-gradient(145deg,rgba(20,38,65,.96),rgba(10,23,42,.92)); border-color:var(--line); border-radius:14px; box-shadow:0 14px 38px rgba(0,0,0,.18); } .metric { position:relative; overflow:hidden; } .metric:before { content:""; position:absolute; inset:0 auto 0 0; width:3px; background:linear-gradient(#65a8ff,#34d399); } .label { color:#8fa8c8; letter-spacing:.09em; } .value { color:#f5f9ff; letter-spacing:-.035em; } .split { gap:16px; }
    button,a.button { border-color:rgba(149,193,255,.45); background:linear-gradient(135deg,#3478dc,#2260bd); border-radius:9px; box-shadow:0 6px 18px rgba(32,96,189,.23); transition:transform .16s ease,filter .16s ease; } button:hover,a.button:hover { transform:translateY(-1px); filter:brightness(1.12); } .ok,.bad,.warn { display:inline-flex; padding:3px 8px; border-radius:999px; font-size:12px; } .ok { color:#6ee7b7; background:rgba(52,211,153,.12); } .bad { color:#fda4af; background:rgba(251,113,133,.12); } .warn { color:#fde68a; background:rgba(251,191,36,.12); } code { background:rgba(101,168,255,.1); border-color:rgba(101,168,255,.22); color:#bcd7ff; } th,td { border-color:var(--line); padding:12px 10px; } th { color:#89a3c4; background:rgba(5,15,30,.23); } a { color:#8bbdff; } @media(max-width:1050px) { .grid { grid-template-columns:repeat(3,minmax(0,1fr)); } } @media(max-width:700px) { main { padding:20px 14px 40px; } .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } table { display:block; overflow-x:auto; white-space:nowrap; } } @media(max-width:460px) { .grid { grid-template-columns:1fr; } }
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
      <div class="panel metric"><div class="label">Fork Mode</div><div class="value" id="forkMode">loading</div><div class="muted" id="payoutTxType"></div></div>
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
      <table><thead><tr><th>Wallet</th><th>Confirmed TKM</th><th>Pending Round TKM</th><th>Total TKM</th></tr></thead><tbody id="balances"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Workers</h2>
      <table><thead><tr><th>Wallet</th><th>Worker</th><th>Accepted</th><th>Rejected</th><th>Round Shares</th><th>Last Seen</th></tr></thead><tbody id="miners"></tbody></table>
    </section>

    <section class="section panel">
      <h2>Recent Payouts</h2>
      <table><thead><tr><th>Wallet</th><th>Amount</th><th>Status</th><th>Transaction</th><th>Created</th></tr></thead><tbody id="payments"></tbody></table>
      <div class="pager"><button id="paymentsPrev">Previous</button><span id="paymentsPage" class="muted">Page 1 of 1</span><button id="paymentsNext">Next</button></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const money = (v) => (Number(v || 0)).toFixed(8) + ' TKM';
    const paymentsPageSize = 25;
    let paymentsPage = 0;
    let paymentsRows = [];
    const yesno = (v) => v ? '<span class="ok">yes</span>' : '<span class="bad">no</span>';
    function row(cells) { return '<tr>' + cells.map(v => '<td>' + String(v ?? '') + '</td>').join('') + '</tr>'; }
    function txLink(hash) { return hash && explorerURL ? '<a href="' + explorerURL + '/tx/' + hash + '" target="_blank" rel="noopener">' + hash + '</a>' : (hash || '-'); }
    let explorerURL = '';
    function kv(k, v) { return '<tr><th>' + k + '</th><td>' + String(v ?? '') + '</td></tr>'; }
    function errText(v) { return v ? '<span class="bad">' + String(v) + '</span>' : ''; }
    function networkText(n) {
      const parts = [];
      if (n && n.quantumResistantActive) parts.push('PQ');
      if (n && n.privacyCommitmentActive) parts.push('Privacy');
      return parts.length ? parts.join(' + ') : 'Legacy';
    }
    function networkHTML(n) {
      if (!n) return 'loading';
      return '<span class="' + (n.payoutReady ? 'ok' : 'warn') + '">' + networkText(n) + '</span>';
    }
    function renderPayments() {
      const totalPages = Math.max(1, Math.ceil(paymentsRows.length / paymentsPageSize));
      paymentsPage = Math.min(Math.max(0, paymentsPage), totalPages - 1);
      const start = paymentsPage * paymentsPageSize;
      const visible = paymentsRows.slice(start, start + paymentsPageSize);
      $('payments').innerHTML = visible.map(p => row([p.wallet, money(p.amountAntd), p.status, txLink(p.txHash), new Date(p.createdAt).toLocaleString()])).join('') || row(['No payouts yet', '', '', '', '']);
      $('paymentsPage').textContent = 'Page ' + (paymentsPage + 1) + ' of ' + totalPages + ' (' + paymentsRows.length + ' payouts)';
      $('paymentsPrev').disabled = paymentsPage <= 0;
      $('paymentsNext').disabled = paymentsPage >= totalPages - 1;
    }
    async function load() {
      const res = await fetch('/api/admin/status');
      const s = await res.json();
      explorerURL = s.explorerURL || '';
      const b = s.poolWalletBalance || {};
      const n = s.network || {};
      $('latestBalance').innerHTML = b.latestError ? errText(b.latestError) : money(b.latestAntd);
      $('latestBlock').textContent = b.latestBlock !== undefined ? 'block ' + b.latestBlock : '';
      $('spendableBalance').innerHTML = b.confirmedError ? errText(b.confirmedError) : (b.lowBalance ? '<span class="warn">' + money(b.spendableAntd) + '</span>' : money(b.spendableAntd));
      $('confirmedBlock').textContent = b.confirmedError ? '' : ((b.payoutStatus || '') + (b.confirmedBlock !== undefined ? ' at confirmed block ' + b.confirmedBlock : ''));
      $('owedBalance').textContent = money(s.totalConfirmedMinerBalanceAntd);
      $('pendingBalance').textContent = 'pending round ' + money(s.totalPendingRoundAntd);
      $('redisStatus').innerHTML = s.redis && s.redis.ok ? '<span class="ok">online</span>' : '<span class="bad">offline</span>';
      $('redisBytes').textContent = s.redis && s.redis.ok ? String(s.redis.stateBytes || 0) + ' bytes saved' : ((s.redis && s.redis.error) || '');
      $('forkMode').innerHTML = networkHTML(n);
      $('payoutTxType').textContent = 'payout tx type ' + (n.payoutTxType || 'default');
      const payoutStatus = b.shieldedPayoutMode ? '<span class="ok">' + (b.payoutStatus || 'shielded prover ready') + '</span>' : (b.confirmedError ? errText(b.confirmedError) : (b.lowBalance ? '<span class="warn">' + (b.payoutStatus || 'low pool wallet balance') + '</span>' : '<span class="ok">' + (b.payoutStatus || 'ready') + '</span>'));
      $('walletRows').innerHTML = kv('Pool wallet', s.poolWallet) + kv('Payout status', payoutStatus) + kv('Latest balance', b.latestError ? errText(b.latestError) : money(b.latestAntd)) + kv('Confirmed balance', b.confirmedError ? errText(b.confirmedError) : money(b.confirmedAntd)) + kv('Pending balance', b.pendingError ? errText(b.pendingError) : (b.pendingAntd !== undefined ? money(b.pendingAntd) : '-')) + kv('Usable balance', b.availableAntd !== undefined ? money(b.availableAntd) : '-') + kv('Reserve', money(s.payoutReserveAntd)) + kv('Spendable', b.confirmedError ? errText(b.confirmedError) : money(b.spendableAntd)) + kv('Total miner balance owed', b.totalOwedAntd !== undefined ? money(b.totalOwedAntd) : money(s.totalConfirmedMinerBalanceAntd)) + kv('Estimated next tx fee', b.estimatedTxFeeAntd !== undefined ? money(b.estimatedTxFeeAntd) : (b.feeEstimateError ? errText(b.feeEstimateError) : '-')) + kv('Spendable after next fee', b.spendableAfterFeeAntd !== undefined ? money(b.spendableAfterFeeAntd) : '-') + kv('Next payout', b.nextPayoutAntd !== undefined ? money(b.nextPayoutAntd) + ' to ' + b.nextPayoutWallet : '-') + kv('Payout tx type', n.payoutTxType || 'default') + kv('Pool wallet algorithm', n.poolWalletAlgorithm || (n.poolWalletAlgorithmError ? errText(n.poolWalletAlgorithmError) : '-')) + kv('Quantum active', yesno(n.quantumResistantActive)) + kv('Privacy commitments active', yesno(n.privacyCommitmentActive)) + kv('Shielded prover configured', yesno(n.shieldedPayoutProverConfigured)) + kv('Shielded payouts enabled', yesno(n.shieldedPayoutsEnabled)) + kv('Payout gate', n.payoutReady ? '<span class="ok">ready</span>' : '<span class="warn">' + (n.payoutBlockedReason || 'blocked') + '</span>') + kv('Password configured', yesno(s.poolWalletPasswordConfigured)) + kv('Daemon coinbase', s.daemonCoinbaseError ? errText(s.daemonCoinbaseError) : s.daemonCoinbase) + kv('Rewards go to pool wallet', yesno(s.poolWalletIsDaemonCoinbase));
      $('runtimeRows').innerHTML = kv('Public URL', s.publicURL) + kv('HTTP bind', s.http) + kv('Stratum public', s.stratum) + kv('Stratum bind', s.stratumBind) + kv('Explorer', s.explorerURL || '-') + kv('Node RPC', s.nodeRPC) + kv('Work method', s.workMethod) + kv('Daemon coinbase', s.daemonCoinbaseError ? errText(s.daemonCoinbaseError) : s.daemonCoinbase) + kv('Current height', (s.work && s.work.height) || 0) + kv('Total shares', s.totalShares) + kv('Workers', s.workerCount) + kv('Connected miners', s.authorizedSessions ?? s.connectedSessions ?? 0) + kv('Uptime seconds', s.uptimeSeconds) + kv('Redis', (s.redis && s.redis.addr) + ' db ' + (s.redis && s.redis.db) + ' key ' + (s.redis && s.redis.stateKey));
      $('payoutRows').innerHTML = kv('Auto pay', yesno(s.autoPay)) + kv('Payment mode', s.paymentMode) + kv('Block reward', money(s.blockRewardAntd)) + kv('Pool fee', s.feePercent + '%') + kv('Minimum payout', money(s.minPayoutAntd)) + kv('Configured maximum per tx', money(s.maxPayoutPerTxAntd)) + kv('Effective maximum per tx', money(s.effectiveMaxPayoutPerTxAntd || s.maxPayoutPerTxAntd)) + kv('Payment interval', s.paymentIntervalSeconds + ' seconds') + kv('Work poll interval', s.workPollIntervalMs + ' ms') + kv('Confirmations for scheduled pay', s.paymentConfirmations) + kv('Shielded payout prover', yesno(n.shieldedPayoutProverConfigured)) + kv('Shielded payout mode', yesno(n.shieldedPayoutsEnabled)) + kv('Privacy commitment time', n.privacyCommitmentTime ? new Date(Number(n.privacyCommitmentTime) * 1000).toISOString() : '-') + kv('Quantum-resistant time', n.quantumResistantTime ? new Date(Number(n.quantumResistantTime) * 1000).toISOString() : '-') + kv('Recent payment records', s.paymentCount);
      const wallets = Array.from(new Set([...Object.keys(s.balances || {}), ...Object.keys(s.pendingBalances || {})]));
      $('balances').innerHTML = wallets.map(w => {
        const confirmed = (s.balances || {})[w] || 0;
        const pending = (s.pendingBalances || {})[w] || 0;
        return row([w, money(confirmed), money(pending), money(confirmed + pending)]);
      }).join('') || row(['No balances yet', money(0), money(0), money(0)]);
      $('miners').innerHTML = (s.miners || []).map(m => row([m.wallet, m.worker || '-', m.acceptedShares, m.rejectedShares, m.roundShares || 0, new Date(m.lastSeen).toLocaleString()])).join('') || row(['No workers connected', '', '', '', '', '']);
      paymentsRows = (s.payments || []).slice().reverse();
      renderPayments();
    }
    $('paymentsPrev').onclick = () => { paymentsPage--; renderPayments(); };
    $('paymentsNext').onclick = () => { paymentsPage++; renderPayments(); };
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

func shareResponseError(accepted bool, reason string) any {
	if accepted {
		return nil
	}
	return reason
}

// RandomX returns raw little-endian bytes; targets are big-endian integers.
func randomXMeetsTarget(raw, target string) bool {
	b, err := hex.DecodeString(trimHex(raw))
	if err != nil || len(b) != 32 {
		return false
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return digestMeetsTarget(hex.EncodeToString(b), target)
}

// Public responses expose payment progress, never internal payout diagnostics.
func publicPayments(payments []Payment) []Payment {
	out := append([]Payment{}, payments...)
	for i := range out {
		state := strings.SplitN(out[i].Status, ":", 2)[0]
		switch state {
		case "sent", "confirmed", "unconfirmed", "pending", "waiting", "failed":
			out[i].Status = state
		default:
			out[i].Status = "waiting"
		}
		out[i].RecipientViewKey = ""
	}
	return out
}
func publicNetworkStatus(status NetworkStatus) NetworkStatus {
	status.HeadError = ""
	status.PrivacyCommitmentError = ""
	status.PoolWalletAlgorithmError = ""
	status.ShieldedPayoutProverError = ""
	status.PayoutBlockedReason = ""
	return status
}

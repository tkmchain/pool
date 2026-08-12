package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendShieldedPaymentCallsConfiguredProver(t *testing.T) {
	const (
		poolWallet = "0xf03a2a24c8926dba5a44301c751aec047b60b0a6"
		toWallet   = "0x4441d6fed0836b77a503e0b2788bfed6fd8c23a8"
		txHash     = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		token      = "test-token"
	)
	var got ShieldedPayoutRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if auth := r.Header.Get("authorization"); auth != "Bearer "+token {
			t.Fatalf("authorization = %q", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(ShieldedPayoutResponse{TxHash: txHash})
	}))
	defer server.Close()

	pool := &Pool{
		cfg: Config{
			PoolWallet:                poolWallet,
			RedisStateKey:             "test:payouts",
			PrivacyCommitmentTime:     tkmPrivacyQuantumActivationUnix,
			QuantumResistantTime:      tkmPrivacyQuantumActivationUnix,
			ShieldedPayoutProverURL:   server.URL,
			ShieldedPayoutProverToken: token,
		},
		rpc: &RPCClient{client: server.Client()},
	}
	payment := Payment{Wallet: toWallet, Amount: 5, CreatedAt: time.Unix(1786428000, 0).UTC()}

	hash, err := pool.sendShieldedPayment(context.Background(), payment, pqTxTypeHex)
	if err != nil {
		t.Fatalf("sendShieldedPayment returned error: %v", err)
	}
	if hash != txHash {
		t.Fatalf("tx hash = %q, want %q", hash, txHash)
	}
	if got.RequestID == "" || len(got.RequestID) != 64 {
		t.Fatalf("request id = %q, want 64 hex chars", got.RequestID)
	}
	if got.PoolWallet != poolWallet || got.To != toWallet {
		t.Fatalf("request wallets = pool %q to %q", got.PoolWallet, got.To)
	}
	if got.AmountWei != "0x4563918244f40000" || got.AmountAntd != 5 {
		t.Fatalf("request amount = %f %s", got.AmountAntd, got.AmountWei)
	}
	if got.PayoutTxType != pqTxTypeHex {
		t.Fatalf("payout tx type = %q", got.PayoutTxType)
	}
}

func TestSendShieldedPaymentCapsLargeAmountToUint64CircuitLimit(t *testing.T) {
	const (
		poolWallet = "0xf03a2a24c8926dba5a44301c751aec047b60b0a6"
		toWallet   = "0x4441d6fed0836b77a503e0b2788bfed6fd8c23a8"
		txHash     = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	var got ShieldedPayoutRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(ShieldedPayoutResponse{TxHash: txHash})
	}))
	defer server.Close()

	pool := &Pool{
		cfg: Config{
			PoolWallet:              poolWallet,
			RedisStateKey:           "test:payouts",
			ShieldedPayoutProverURL: server.URL,
		},
		rpc: &RPCClient{client: server.Client()},
	}

	hash, err := pool.sendShieldedPayment(context.Background(), Payment{
		Wallet:    toWallet,
		Amount:    1000,
		CreatedAt: time.Unix(1786428000, 0).UTC(),
	}, pqTxTypeHex)
	if err != nil {
		t.Fatalf("sendShieldedPayment returned error: %v", err)
	}
	if hash != txHash {
		t.Fatalf("tx hash = %q, want %q", hash, txHash)
	}
	if round(got.AmountAntd) != shieldedMaxPayoutPerTxAntd {
		t.Fatalf("amountAntd = %.8f, want %.8f", got.AmountAntd, shieldedMaxPayoutPerTxAntd)
	}
	amountWei, ok := parseBigFlexible(got.AmountWei)
	if !ok {
		t.Fatalf("amountWei = %q is not parseable", got.AmountWei)
	}
	if amountWei.Sign() <= 0 || amountWei.BitLen() > 64 {
		t.Fatalf("amountWei = %s exceeds uint64 circuit limit", amountWei)
	}
	wantWei := "0x" + antdToWeiInt(shieldedMaxPayoutPerTxAntd).Text(16)
	if got.AmountWei != wantWei {
		t.Fatalf("amountWei = %q, want %q", got.AmountWei, wantWei)
	}
}

func TestEffectiveShieldedPayoutAmountForNoteCapsToAvailableNote(t *testing.T) {
	got := effectiveShieldedPayoutAmountForNote(10.63213925, "0x4563918244f40000")
	if got != 5 {
		t.Fatalf("effective payout = %.8f, want 5.00000000", got)
	}
}

func TestEffectiveShieldedPayoutAmountForNoteFloorsNoteWeiToPoolPrecision(t *testing.T) {
	got := effectiveShieldedPayoutAmountForNote(5, "4999999999999999999")
	if got != 4.99999999 {
		t.Fatalf("effective payout = %.8f, want 4.99999999", got)
	}
	if antdToWeiInt(got).String() != "4999999990000000000" {
		t.Fatalf("effective payout wei = %s, want 4999999990000000000", antdToWeiInt(got))
	}
}

func TestSendShieldedPaymentRejectsInvalidProverHash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ShieldedPayoutResponse{TxHash: "0x1234"})
	}))
	defer server.Close()

	pool := &Pool{
		cfg: Config{
			PoolWallet:              "0xf03a2a24c8926dba5a44301c751aec047b60b0a6",
			RedisStateKey:           "test:payouts",
			ShieldedPayoutProverURL: server.URL,
		},
		rpc: &RPCClient{client: server.Client()},
	}
	_, err := pool.sendShieldedPayment(context.Background(), Payment{
		Wallet:    "0x4441d6fed0836b77a503e0b2788bfed6fd8c23a8",
		Amount:    1,
		CreatedAt: time.Now(),
	}, "")
	if err == nil || !strings.Contains(err.Error(), "invalid tx hash") {
		t.Fatalf("error = %v, want invalid tx hash", err)
	}
}

func TestShieldedPayoutHealthURL(t *testing.T) {
	got, err := shieldedPayoutHealthURL("http://127.0.0.1:8787/payout?unused=1")
	if err != nil {
		t.Fatalf("shieldedPayoutHealthURL returned error: %v", err)
	}
	if got != "http://127.0.0.1:8787/healthz" {
		t.Fatalf("health URL = %q, want healthz on the configured prover host", got)
	}
}

func TestShieldedPayoutRequestIDIsStableUntilSentSequenceChanges(t *testing.T) {
	wallet := "0x4441d6fed0836b77a503e0b2788bfed6fd8c23a8"
	pool := &Pool{
		cfg: Config{
			PoolWallet:    "0xf03a2a24c8926dba5a44301c751aec047b60b0a6",
			RedisStateKey: "test:payouts",
		},
		payments: []Payment{{Wallet: wallet, Amount: 5, Status: "waiting: shielded prover: timeout"}},
	}
	payment := Payment{Wallet: wallet, Amount: 5}

	first := pool.shieldedPayoutRequestID(payment)
	second := pool.shieldedPayoutRequestID(payment)
	if first != second {
		t.Fatalf("request id changed across retry: %q vs %q", first, second)
	}

	pool.payments = append(pool.payments, Payment{Wallet: wallet, Amount: 5, Status: "sent"})
	third := pool.shieldedPayoutRequestID(payment)
	if third == first {
		t.Fatalf("request id should change after a sent payout sequence advances")
	}
}

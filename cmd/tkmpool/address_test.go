package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestNormalizeAddressCanonicalizesCase(t *testing.T) {
	lower := "0xf03a2a24c8926dba5a44301c751aec047b60b0a6"
	mixed := "0xF03a2a24C8926dBA5A44301C751aec047B60B0a6"

	if got := normalizeAddress(mixed); got != lower {
		t.Fatalf("normalizeAddress(%q) = %q, want %q", mixed, got, lower)
	}

	wallet, worker := parseAuthorize(json.RawMessage(fmt.Sprintf(`["%s.rig1"]`, mixed)))
	if wallet != lower {
		t.Fatalf("parseAuthorize wallet = %q, want %q", wallet, lower)
	}
	if worker != "rig1" {
		t.Fatalf("parseAuthorize worker = %q, want rig1", worker)
	}
}

func TestApplyPayoutStateMergesSameAddressWithDifferentCase(t *testing.T) {
	lower := "0xf03a2a24c8926dba5a44301c751aec047b60b0a6"
	mixed := "0xF03a2a24C8926dBA5A44301C751aec047B60B0a6"
	earlier := time.Unix(10, 0)
	later := time.Unix(20, 0)
	p := &Pool{
		balances: make(map[string]float64),
		miners:   make(map[string]*Miner),
	}

	p.applyPayoutStateLocked(PayoutState{
		Balances: map[string]float64{
			lower: 1.25,
			mixed: 2.75,
		},
		Payments: []Payment{{Wallet: mixed, Amount: 0.5}},
		Miners: map[string]Miner{
			lower + ".rig1": {Wallet: lower, Worker: "rig1", AcceptedShares: 2, RejectedShares: 1, RoundShares: 2, LastSeen: earlier},
			mixed + ".rig1": {Wallet: mixed, Worker: "rig1", AcceptedShares: 3, RejectedShares: 4, RoundShares: 5, LastSeen: later},
		},
	})

	if len(p.balances) != 1 || p.balances[lower] != 4 {
		t.Fatalf("balances = %#v, want one canonical balance of 4", p.balances)
	}
	if len(p.payments) != 1 || p.payments[0].Wallet != lower {
		t.Fatalf("payments = %#v, want canonical wallet %s", p.payments, lower)
	}
	if len(p.miners) != 1 {
		t.Fatalf("miners = %#v, want one canonical miner", p.miners)
	}
	miner := p.miners[lower+".rig1"]
	if miner == nil {
		t.Fatalf("canonical miner key missing: %#v", p.miners)
	}
	if miner.AcceptedShares != 5 || miner.RejectedShares != 5 || miner.RoundShares != 7 || !miner.LastSeen.Equal(later) {
		t.Fatalf("merged miner = %#v, shares/lastSeen not merged correctly", miner)
	}
}

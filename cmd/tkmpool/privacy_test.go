package main

import "testing"

func TestPrivacyConfigRequiresTorInStrictMode(t *testing.T) {
	if err := validatePrivacyConfig(Config{PrivacyStrict: true}); err == nil {
		t.Fatal("strict privacy accepted without Tor")
	}
	for _, proxy := range []string{"http://127.0.0.1:9050", "socks5://127.0.0.1", "socks5://user:pass@127.0.0.1:9050"} {
		if err := validatePrivacyConfig(Config{TorSOCKS5Proxy: proxy}); err == nil {
			t.Fatalf("accepted unsafe Tor proxy %q", proxy)
		}
	}
}

func TestPrivacyConfigAllowsLocalDaemonAndSecureRemoteProver(t *testing.T) {
	cfg := Config{PrivacyStrict: true, TorSOCKS5Proxy: "socks5://127.0.0.1:9050", NodeRPC: "http://127.0.0.1:8545", ShieldedPayoutProverURL: "https://prover.example/payout"}
	if err := validatePrivacyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	client, err := newPrivacyHTTPClient(cfg)
	if err != nil || client.Transport == nil {
		t.Fatalf("privacy HTTP client unavailable: %v", err)
	}
}

func TestOnionOnlyRejectsClearnetEndpoints(t *testing.T) {
	cfg := Config{OnionOnly: true, TorSOCKS5Proxy: "socks5://127.0.0.1:9050", NodeRPC: "https://node.example/rpc"}
	if err := validatePrivacyConfig(cfg); err == nil {
		t.Fatal("onion-only mode accepted a clearnet node RPC")
	}
	cfg.NodeRPC = "http://127.0.0.1:8545"
	if err := validatePrivacyConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

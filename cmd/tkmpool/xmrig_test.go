package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestXMRigLoginParsesWalletAndWorker(t *testing.T) {
	raw := json.RawMessage(`{"login":"0x4441d6fEd0836B77a503e0B2788bfEd6FD8c23A8.worker1","pass":"x"}`)
	wallet, worker := parseXMRigLogin(raw)
	if wallet != "0x4441d6fed0836b77a503e0b2788bfed6fd8c23a8" {
		t.Fatalf("wallet = %s", wallet)
	}
	if worker != "worker1" {
		t.Fatalf("worker = %s", worker)
	}
}

func TestXMRigLoginUsesSeparateRigIDForUsername(t *testing.T) {
	raw := json.RawMessage(`{"login":"@alice#abc2345","rigid":"worker-1"}`)
	if got := parseXMRigLoginText(raw); got != "@alice#abc2345.worker-1" {
		t.Fatalf("login with rigid = %q", got)
	}
}

func TestPoolResolvesShield3UsernameToPayoutIdentity(t *testing.T) {
	address := "0xf03a2a24c8926dba5a44301c751aec047b60b0a6"
	code := testShield3PaymentCode(address)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string   `json:"method"`
			Params []string `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Method != "tkmname_resolve" || len(request.Params) != 1 || request.Params[0] != "@alice#abc2345" {
			t.Fatalf("username RPC request = %#v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
			"chainId": 8979, "username": "alice", "address": address, "paymentCode": code,
		}})
	}))
	defer server.Close()
	p := &Pool{rpc: &RPCClient{endpoint: server.URL, client: server.Client()}}
	wallet, worker, recipient, err := p.resolveMinerLogin(context.Background(), "@alice#abc2345.rig-1")
	if err != nil {
		t.Fatal(err)
	}
	if wallet != address || worker != "rig-1" || recipient != code {
		t.Fatalf("resolved login = (%q, %q, %t), want wallet, worker, code", wallet, worker, recipient == code)
	}
}

func testShield3PaymentCode(address string) string {
	addressBytes, _ := hex.DecodeString(strings.TrimPrefix(address, "0x"))
	items := []byte{3, 0x82, 0x23, 0x13, 0x94}
	items = append(items, addressBytes...)
	inner := append([]byte{byte(0xc0 + len(items))}, items...)
	root := append([]byte{byte(0xc0 + len(inner))}, inner...)
	return "tkmshield3." + base64.RawURLEncoding.EncodeToString(root)
}

func TestTKMXMRigBlobAndNonce(t *testing.T) {
	work := Work{SealHash: "0x1111111111111111111111111111111111111111111111111111111111111111"}
	blob := tkmXMRigBlob(work)
	if len(blob) != 80 {
		t.Fatalf("blob length = %d, want 80 hex chars", len(blob))
	}
	if blob != "11111111111111111111111111111111111111111111111111111111111111110000000000000000" {
		t.Fatalf("blob = %s", blob)
	}
	if nonce := normalizeTKMNonce("78563412"); nonce != "0x0000000078563412" {
		t.Fatalf("nonce = %s", nonce)
	}
	if nonce := normalizeTKMNonce("0x0000000078563412"); nonce != "0x0000000078563412" {
		t.Fatalf("full nonce = %s", nonce)
	}
}

func TestParseXMRigShareSubmission(t *testing.T) {
	raw := json.RawMessage(`{"id":"abc","job_id":"0xjob","nonce":"78563412","result":"abcdef"}`)
	job, nonce, digest := parseShareSubmission(raw)
	if job != "0xjob" || nonce != "78563412" || digest != "abcdef" {
		t.Fatalf("got job=%q nonce=%q digest=%q", job, nonce, digest)
	}
}

func TestXMRigShareTarget(t *testing.T) {
	full := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if target := xmrigShareTarget("0x" + full); target != full {
		t.Fatalf("target = %s", target)
	}
	if target := xmrigShareTarget("1234567890abcdef"); target != "0000000000000000000000000000000000000000000000001234567890abcdef" {
		t.Fatalf("target = %s", target)
	}
}

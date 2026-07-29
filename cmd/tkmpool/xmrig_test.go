package main

import (
	"encoding/json"
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

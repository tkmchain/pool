# TKM Pool

Standalone mining pool scaffold for `tkmchain/go-tkmchain`.

It provides:

- Stratum TCP listener for external miners.
- JSON-RPC polling against a synced `gtkm` node using `miner_getWork` by default. `randomx_getWork` and auto fallback are also configurable.
- Fork-aware TKM privacy and post-quantum payout checks.
- Share accounting by wallet address.
- Payment ledger with proportional payout calculation.
- Optional guarded payout submission through the node RPC.
- Built-in HTML dashboard.

## Run

```sh
go run ./cmd/tkmpool -config config.example.json
```

Open `http://127.0.0.1:8080`.

## Node

Run a full Tkmchain node with RandomX/miner APIs enabled:

```sh
gtkm --syncmode=full --http --http.addr 127.0.0.1 \
  --http.api eth,net,web3,miner,randomx,tkm,tkmprivacy \
  --mine --miner.threads=1 --miner.etherbase=0xYourPoolWallet
```

If your daemon logs `the method randomx_getWork does not exist/is not available`, keep `"workMethod": "miner"` in `config.example.json`. If it logs `pending work is not ready`, the pool can reach the daemon but the daemon has not made a usable mining job available yet. Confirm the node is synced, has mining enabled, and has a valid `--miner.etherbase`.

## Miner

The pool supports the patched TKM XMRig miner in `~/xmrig`. The miner uses algorithm `rx/tkm`, which hashes the exact TKMChain RandomX input used by `gtkm`:

```text
RandomX(seedHash, sealHash || 8-byte header nonce)
```

Point XMRig at the pool Stratum endpoint:

```sh
~/xmrig/build/xmrig -a rx/tkm -o 127.0.0.1:33330 -u 0xYourPayoutWallet.worker1 -p x
```

Or start it with the example config:

```sh
~/xmrig/build/xmrig -c ~/pool/xmrig-tkm.example.json
```

Use the payout wallet as username. Worker names are supported with `0xWallet.worker1`. Pool share acceptance uses `shareTarget`; block candidates are still checked against the daemon work target before submission to `gtkm`.

The pool also keeps the older `mining.subscribe`, `mining.authorize`, and array-style `mining.submit` flow for existing miners. XMRig uses the newer `login`, `job`, `submit`, and `keepalived` flow.

### Build the patched XMRig

Install build dependencies, then configure and build XMRig:

```sh
cd ~/xmrig
sudo apt-get install -y build-essential cmake libuv1-dev libssl-dev
cmake -S . -B build -DWITH_OPENCL=OFF -DWITH_CUDA=OFF -DWITH_HWLOC=OFF
cmake --build build -j$(nproc)
```

If you want hwloc CPU topology support, install `libhwloc-dev` and remove `-DWITH_HWLOC=OFF`.

## Payments

The pool accounts the configured `blockRewardAntd` proportionally when the daemon accepts a submitted block candidate. Balances and payment history are persisted only to Redis. On startup the pool connects to Redis and writes an empty state if the key does not exist, so Redis must be running before the pool starts. Timer autopay checks the pool wallet balance at `eth_blockNumber - paymentConfirmations`. Payouts triggered by a found block use the latest balance immediately. Both paths only send payouts that fit inside the spendable pool balance after `payoutReserveAntd` is kept aside. Payouts are chunked: each transaction sends at most `maxPayoutPerTxAntd`, and if confirmed spendable pool balance is smaller the pool sends the available amount as long as it is at least `minPayoutAntd`. Failed payout transactions are recorded in the payment list and the miner balance is kept for the next run.

Automatic payment broadcasting is disabled by default. To enable it, set `autoPay` to `true`, set `minPayoutAntd` and `maxPayoutPerTxAntd`, and make sure `poolWallet` is a funded hot wallet. For password mode, set `poolWalletPassword`; the pool calls `tkm_sendTransactionWithPassphrase` for each payout transaction, so the wallet is not globally unlocked. If `poolWalletPassword` is empty, use Clef or another node signer with `eth_sendTransaction` instead.

For the production privacy/PQ hardfork at `2026-08-10 06:00:00 UTC`, keep these fields aligned with the chain:

```json
{
  "privacyCommitmentTime": 1786341600,
  "quantumResistantTime": 1786341600
}
```

After `quantumResistantTime`, payout transactions are sent as TKM PQ transaction type `0x6`. The pool verifies the local `poolWallet` keystore with `tkm_accountAlgorithm` and expects `ML-DSA-87` when `poolWalletPassword` is configured.

After privacy commitments are active, transparent payouts are held instead of broadcast because the chain rejects non-`TKMSHIELD1` user transactions. Mining and share accounting continue, block rewards still accrue to the configured etherbase, and balances remain in Redis until a real shielded payout prover is configured for pool spending.

To enable shielded payouts, run a separate prover service on a private host that has the shielded note wallet and proving key. Then set these pool config fields and restart the pool:

```json
{
  "shieldedPayoutProverURL": "http://127.0.0.1:8787/payout",
  "shieldedPayoutProverToken": "change-this-token"
}
```

The pool sends one `POST` per payout:

```json
{
  "requestId": "stable-idempotency-key",
  "poolWallet": "0xYourPoolWallet",
  "to": "0xMinerPayoutWallet",
  "amountAntd": 5,
  "amountWei": "0x4563918244f40000",
  "payoutTxType": "0x6",
  "privacyCommitmentTime": 1786341600,
  "quantumResistantTime": 1786341600,
  "createdAt": "2026-08-11T00:00:00Z"
}
```

The active shielded spend circuit constrains note values to 64-bit wei. In shielded mode the pool automatically chunks any larger miner balance into per-transaction payouts of at most `18.44674407` TKM, even if `maxPayoutPerTxAntd` is configured higher. Later payout cycles continue paying the remaining balance.

The pool checks `GET /healthz` on the configured prover host before attempting shielded payouts. If the prover is reachable but has no spendable shielded notes, `/api/status` reports:

```text
shielded payout prover has no spendable shielded notes
```

That means the prover service and proving key can be healthy while payout liquidity is still missing. Fund the prover by importing real shielded notes with known on-chain commitments and Merkle witnesses; do not create synthetic local notes.

For pool-owned liquidity, use the prover's authenticated deposit endpoint instead of sending TKM to mainking:

```sh
curl -sS http://127.0.0.1:8787/deposit \
  -H "Authorization: Bearer <shieldedPayoutProverToken>" \
  -H "Content-Type: application/json" \
  -d '{"requestId":"pool-liquidity-001","amountAntd":5}'
```

The deposit locks transparent TKM in `ShieldedPoolAddress`, proves that the deposited value is represented by shielded output commitments, and imports the resulting note into the prover's `notes.json`.

Use a stable `requestId` only for retries of the same deposit. Reusing a deposit `requestId` returns the recorded transaction instead of creating a second funding transaction.

The TKM node behind the prover must run the deposit-capable shielded verifier. Older node binaries reject these deposit proofs.

If `shieldedPayoutProverToken` is set, the pool sends `Authorization: Bearer <token>`. The prover must build a real `TKMSHIELD1` envelope, sign and submit the transaction to the TKM node, then return:

```json
{ "txHash": "0x..." }
```

Only after a valid 32-byte transaction hash is returned does the pool mark the payout as `sent` and deduct the miner's Redis balance. If the prover is down or returns an error, the payout remains owed and is retried with the same `requestId` sequence until a sent payout is recorded. The prover should therefore persist request IDs and return the same hash for duplicate requests.

Redis setup for payment state:

```sh
sudo systemctl enable --now redis-server
redis-cli GET tkmpool:payout-state
```

The pool saves balances, payment history, miner wallet addresses, worker names, accepted/rejected shares, round shares, last-seen timestamps, and total share count to `redisStateKey` after miner or payout updates. The HTML dashboard reads this Redis-backed state through `/api/status`. Keep Redis bound to localhost unless you configure authentication and firewall rules.

Manual payout processing is available from the dashboard button or with:

```sh
curl -X POST http://127.0.0.1:8080/api/payments/run
```

## Clef Autopay Setup

Clef should sign transactions for the node, while the pool only talks to the node RPC. Keep all Clef and node RPC listeners bound to `127.0.0.1`.

1. Create or import the pool payout wallet in the Egypt keystore:

```sh
./gtkm account new --datadir ~/.tkmchain/egypt
```

2. Initialize Clef and set the password for the pool wallet. Use the same keystore path that contains `poolWallet`:

```sh
clef --configdir ~/.clef-tkm-egypt init
clef --configdir ~/.clef-tkm-egypt \
  --keystore ~/.tkmchain/egypt/keystore setpw 0xYourPoolWallet
```

3. For unattended autopay, create a restrictive Clef rules file such as `clef-pool-rules.js`. Replace the wallet and max value before using it:

```js
function ApproveListing() {
  return "Approve";
}

function ApproveTx(req) {
  var tx = req.transaction;
  var pool = "0xyourpoolwallet";
  var maxWei = BigInt("100000000000000000000"); // 100 TKM

  if (!tx.from || tx.from.toLowerCase() !== pool) {
    return "Reject";
  }
  if (tx.data && tx.data !== "0x") {
    return "Reject";
  }
  if (!tx.to) {
    return "Reject";
  }
  if (BigInt(tx.value) > maxWei) {
    return "Reject";
  }
  return "Approve";
}
```

4. Start Clef. If your `clef` binary does not support HTTP, use its IPC endpoint and pass that endpoint to `--signer` when starting `gtkm`.

```sh
clef --configdir ~/.clef-tkm-egypt \
  --keystore ~/.tkmchain/egypt/keystore \
  --chainid 8980 \
  --http --http.addr 127.0.0.1 --http.port 8550 \
  --rules clef-pool-rules.js
```

5. Start the Egypt node with mining/RPC APIs enabled:

```sh
./gtkm --egypt --syncmode=full \
  --signer http://127.0.0.1:8550 \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --http.api eth,net,web3,miner,randomx,tkm,tkmprivacy \
  --mine --miner.etherbase=0xYourPoolWallet
```

6. Enable autopay in `config.example.json` or your production config:

```json
{
  "poolWallet": "0xYourPoolWallet",
  "poolWalletPassword": "your-wallet-password",
  "redisAddr": "127.0.0.1:6379",
  "redisPassword": "",
  "redisDB": 0,
  "redisStateKey": "tkmpool:payout-state",
  "blockRewardAntd": 100.0,
  "minPayoutAntd": 5.0,
  "maxPayoutPerTxAntd": 25.0,
  "autoPay": true,
  "paymentIntervalSeconds": 300,
  "paymentConfirmations": 0,
  "payoutReserveAntd": 0.1,
  "rpcTimeoutSeconds": 60,
  "privacyCommitmentTime": 1786341600,
  "quantumResistantTime": 1786341600,
  "shareTarget": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}
```

Start the pool after the node is running:

```sh
go run ./cmd/tkmpool -config config.example.json
```

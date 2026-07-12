# TKM Pool

Standalone mining pool scaffold for `tkmchain/go-tkmchain`.

It provides:

- Stratum TCP listener for external miners.
- JSON-RPC polling against a synced `gtkm` node using `miner_getWork` by default. `randomx_getWork` and auto fallback are also configurable.
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
  --http.api eth,net,web3,miner,randomx \
  --mine --miner.threads=1 --miner.etherbase=0xYourPoolWallet
```

If your daemon logs `the method randomx_getWork does not exist/is not available`, keep `"workMethod": "miner"` in `config.example.json`. If it logs `pending work is not ready`, the pool can reach the daemon but the daemon has not made a usable mining job available yet. Confirm the node is synced, has mining enabled, and has a valid `--miner.etherbase`.

## Miner

Point RandomX miners at the pool stratum endpoint:

```sh
stratum+tcp://127.0.0.1:3333
```

Use the payout wallet as username. Worker names are supported with
`0xWallet.worker1`. Pool share acceptance uses `shareTarget`; block candidates are still checked against the daemon work target before submission.

## Payments

The pool accounts the configured `blockRewardAntd` proportionally when the daemon accepts a submitted block candidate. Balances and payment history are persisted to `payoutStateFile`, so a restart does not erase unpaid miner balances. Autopay checks the pool wallet balance at `eth_blockNumber - paymentConfirmations` and only sends payouts that fit inside that confirmed balance after `payoutReserveAntd` is kept aside. Failed payout transactions are recorded in the payment list and the miner balance is kept for the next run.

Automatic payment broadcasting is disabled by default. To enable it, set `autoPay` to `true`, set `minPayoutAntd`, and make sure `poolWallet` is a funded hot wallet controlled by the node signer. The pool sends payouts through `eth_sendTransaction`; it does not store private keys.

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
  var maxWei = BigInt("100000000000000000000"); // 100 ANTD

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

5. Start the Egypt node with the external signer and mining/RPC APIs enabled:

```sh
./gtkm --egypt --syncmode=full \
  --signer http://127.0.0.1:8550 \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --http.api eth,net,web3,miner,randomx \
  --mine --miner.etherbase=0xYourPoolWallet
```

6. Enable autopay in `config.example.json` or your production config:

```json
{
  "poolWallet": "0xYourPoolWallet",
  "payoutStateFile": "payout-state.json",
  "blockRewardAntd": 100.0,
  "minPayoutAntd": 5.0,
  "autoPay": true,
  "paymentIntervalSeconds": 300,
  "paymentConfirmations": 12,
  "payoutReserveAntd": 0.1,
  "rpcTimeoutSeconds": 60,
  "shareTarget": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
}
```

Start the pool after the node and Clef are running:

```sh
go run ./cmd/tkmpool -config config.example.json
```

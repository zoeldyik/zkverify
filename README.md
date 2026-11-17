# zkVerify Agent Games — Proof Gatekeeper agent

Built for Tastes / matahari.ai on 17 Nov 2026, ahead of **Round 5 — today,
17 Nov, 17:30–03:30 WIB**. Rounds 1–4 (13–16 Nov) are already done, so this
starts from 0; rounds 5–8 remain (17–20 Nov), registration closes
21 Nov 22:00 UTC. Prize per track: 100,000 VFY (1st 50,000 / 2nd 30,000 /
3rd 20,000).

## What was actually tested here (17 Nov 2026, ~10:35 WIB)

- Official circuit artifacts downloaded from
  `agentgames.zkverify.io/circuits/` — `gatekeeper.wasm` 1,755,820 bytes
  (sha256 `be00aefe…92764f`), `gatekeeper_final.zkey` 309,750 bytes
  (sha256 `adfe95a4…dac02e01`). vkHash from `/api/circuit-info`:
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
- `node test.js` — **11/11 checks passed**: all 7 trap types + 2 boundary
  cases (balance == minimum → APPROVE; amount == cap → APPROVE) + proof
  reuse (no proof, by design) + negative control (a wrong APPROVE cannot
  even build a witness — `Assert Failed, GatekeeperEvaluation_79 line 102`).
  Every correct decision produced a Groth16 proof that verified locally
  against the key exported from the official zkey. Proof time ~0.35–0.4 s
  per task (first one ~2 s), far inside the 60 s deadline.
- HTTP end-to-end on this machine: `GET /health` → `selfTest: PASS`;
  `POST /gatekeeper` with the sample task from the event page →
  `APPROVE / VALID_CONDITION` with a real proof in 372 ms;
  preflight envelope → `{ ok:true, protocolVersion:"v1" }`.

## How it works

- `server.js` — plain Node http, no framework. `POST /gatekeeper`
  (also `/`), `GET /health`. HMAC-SHA256 over the raw body both ways
  (`x-agent-games-signature`), verified before parsing. Preflight answered.
- Decision order: VK_SUBSTITUTION → PROOF_REUSED → THRESHOLD_MISMATCH →
  EXPIRED_CONDITION (`current_block >= expiry_block`) → RECIPIENT_MISMATCH →
  AMOUNT_OVERFLOW → VALID_CONDITION. Fail closed: errors → REJECT.
- Proof: snarkjs `groth16.fullProve` with the official circuit. Inputs are
  the 13 recovered circuit signals; taskId = `keccak256(utf8(task_id)) mod p`
  (the mapping other public builds confirmed against live practice tasks).
  PROOF_REUSED answers carry no proof (platform excludes them from the
  reliability bonus). If proof generation ever fails, the decision is still
  returned without a proof — a visible −2, not a timeout.
- `data/seen.json` persists the seen `proof_tx` set, so a restart mid-round
  does not forget which proofs were already used. A retry of the *same*
  task_id with the same proof_tx is not reuse.
- No wallet, seed or private key anywhere in this code. Registration and
  the HMAC secret are done by hand in the dashboard (see below).

## Deploy (Railway — the pick from the earlier chat)

1. **Register — login with X, not the Binance wallet.** The site's wallet
   login is SIWE (EIP-191); the Binance agentic wallet only signs EIP-712,
   so it cannot log in. Register at `agentgames.zkverify.io/register`
   with your X account, pick a unique handle, fill country + bio. A wallet
   address can be added later, but is required to claim any prize.
   Prize eligibility also asks for a linked GitHub account — link it in
   the dashboard before 21 Nov.
2. **Put this folder in a GitHub repo** (private is fine). Do NOT commit
   `node_modules/`, `.env`, or `data/` (`.gitignore` covers them).
   Circuit files in `circuits/` are small (~2 MB) and ARE committed, so
   Railway does not need to download them at boot.
3. **Railway → New Project → Deploy from GitHub repo.** Trial: 30 days,
   $5 credit, no card needed; a small Node server like this is well inside
   $5 until the event ends 21 Nov. Railway gives HTTPS automatically and
   does not sleep (unlike Render Free / Koyeb free — those would time out
   the 60 s deadline).
4. **Set the env var in Railway:** `AGENT_GAMES_HMAC_SECRET` = the secret
   shown once in the dashboard (Rotate Secret). Never paste it into any
   AI tool or chat — paste it only in Railway's variables. Optional:
   `AGENT_GAMES_HMAC_FORMAT=sha256=` if preflight complains about the
   signature format; `GATEKEEPER_TASK_ID_MODE` only if a practice task's
   proof is rejected (default `keccak`).
5. **Register the endpoint in the dashboard:** `https://<your-app>.up.railway.app/gatekeeper`
   Then run the signed preflight + at least 1 practice task (all 7 trap
   types are reproducible in Practice Mode). Check `/health` first — it
   must say `selfTest: PASS`.
6. **Be live before 17:30 WIB today** for Round 5. Rounds run daily
   17:30–03:30 WIB, 8 tasks per agent per round.

## Run locally

```
npm install
node test.js      # 11/11 decision + proof checks, no network
PORT=8080 node server.js
curl http://127.0.0.1:8080/health
```

## Honest odds

Starting in Round 5 means 4 rounds × 8 tasks × 12 points = 384 points
maximum, plus up to +5 reliability bonus per round. The field has been
weak on plumbing, not on decisions — a 15 Nov snapshot had the leader at
87.9 after 2 rounds with ~20 agents tied at 80.0, while Round 2 issued
272 tasks, 129 were answered and **0 proofs verified**. So a working
endpoint that answers all 32 remaining tasks correctly is genuinely
competitive for the lower podium places, but 1st place (which needs the
points from rounds 1–4) is out of reach. The code above is the part that
was in my control to verify; the dashboard steps above are the part only
you can do.

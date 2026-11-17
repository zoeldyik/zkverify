// Proof Gatekeeper agent for zkVerify Agent Games Season 01.
// Built for Tastes / matahari.ai — 17 Nov 2026, ahead of Round 5 (17:30 WIB).
//
// Plain Node.js, no framework. Endpoints:
//   GET  /health     -> { ok, agent, hmacConfigured, selfTest, seenProofs }
//   POST /gatekeeper -> signed task envelope in, signed decision + Groth16 proof out
//   POST /           -> same as /gatekeeper (in case the dashboard registers the bare URL)
//
// Protocol (from https://agentgames.zkverify.io/build and
// https://agentgames.zkverify.io/events/proof-gatekeeper, read 17 Nov 2026):
// - Platform POSTs a JSON envelope; condition fields live under `input`,
//   task_id at envelope level. Verify HMAC-SHA256 over the RAW body first
//   (header x-agent-games-signature), before parsing anything.
// - Decide APPROVE/REJECT with the 7-trap checklist, in this order:
//   VK_SUBSTITUTION, PROOF_REUSED, THRESHOLD_MISMATCH, EXPIRED_CONDITION,
//   RECIPIENT_MISMATCH, AMOUNT_OVERFLOW, else VALID_CONDITION.
//   Boundaries: balance == minimum is valid; current_block >= expiry_block
//   is expired; amount == max_transfer is valid.
// - Generate a Groth16 proof locally with snarkjs + the official circuit
//   (gatekeeper.wasm / gatekeeper_final.zkey, vkHash
//   0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0).
//   The circuit re-checks the same five field checks, so a decision that
//   disagrees with the circuit cannot even build a witness — no proof.
// - PROOF_REUSED answers carry NO proof (the platform excludes them from
//   the reliability bonus). If proof generation fails, still return the
//   decision without a proof instead of hanging (visible -2, not a timeout).
// - Every response is signed the same way over its raw body.
// - Preflight envelopes {"type":"agent-games.preflight.v1"} are answered
//   { ok:true, protocolVersion:"v1" }.
// - Fail closed: any error / uncertainty -> REJECT, never approve by default.
//
// This code never touches a wallet, seed or private key. Registration
// (SIWE / X login) and the HMAC secret are done by hand in the dashboard.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
// HMAC header format: 'hex' (default) or 'sha256=' — switch if preflight
// complains about the signature format.
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
// taskId mapping: 'keccak' (default, confirmed by practice tasks in other
// public builds) — keccak256(utf8(task_id)) mod p. Alternatives: 'numeric',
// 'hex'. Switch only if a practice task's proof is rejected.
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';

const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const SEEN_FILE = path.join(__dirname, 'data', 'seen.json');

// ---- field helpers -------------------------------------------------------
function toField(x) {
  const b = typeof x === 'bigint' ? x : BigInt(x); // decimal or 0x-hex string
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}
function keccak256ModP(buf) {
  return toField(BigInt('0x' + keccak_256(buf)));
}
function taskIdToField(taskId) {
  const id = String(taskId || '');
  if (TASK_ID_MODE === 'numeric') {
    const d = id.replace(/\D/g, '');
    return d ? toField(BigInt(d)) : 0n;
  }
  if (TASK_ID_MODE === 'hex') {
    const h = id.replace(/[^0-9a-fA-F]/g, '');
    return h ? toField(BigInt('0x' + h)) : 0n;
  }
  return keccak256ModP(Buffer.from(id, 'utf8'));
}

// ---- HMAC ----------------------------------------------------------------
function signatureFor(secret, rawBody) {
  const hex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return HMAC_FORMAT === 'sha256=' ? 'sha256=' + hex : hex;
}
function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const expected = Buffer.from(signatureFor(secret, rawBody));
  const actual = Buffer.from(String(headerValue));
  if (expected.length !== actual.length) return false;
  try { return crypto.timingSafeEqual(expected, actual); } catch { return false; }
}

// ---- seen proof_tx set (persisted, so a restart mid-round keeps it) ------
let seenProofTx = new Map(); // proof_tx (lowercase) -> task_id
try {
  const saved = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
  if (saved && typeof saved === 'object') seenProofTx = new Map(Object.entries(saved));
} catch { /* first run: no file yet */ }
function saveSeen() {
  try { fs.writeFileSync(SEEN_FILE, JSON.stringify(Object.fromEntries(seenProofTx))); } catch (e) {
    console.error('[seen] could not persist seen set:', e.message);
  }
}

// ---- decision ------------------------------------------------------------
function decide(task) {
  const registeredVk = String(task.registered_vk || '').toLowerCase();
  const proofVk = String(task.proof_vk || '').toLowerCase();
  if (proofVk !== registeredVk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };

  const proofTx = String(task.proof_tx || '').toLowerCase();
  const taskId = String(task.task_id || '');
  if (proofTx) {
    const prev = seenProofTx.get(proofTx);
    if (prev !== undefined && prev !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    if (prev === undefined) { seenProofTx.set(proofTx, taskId); saveSeen(); }
  }

  if (BigInt(task.public_balance) < BigInt(task.minimum)) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (BigInt(task.current_block) >= BigInt(task.expiry_block)) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (String(task.recipient || '').toLowerCase() !== String(task.condition_recipient || '').toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (BigInt(task.amount) > BigInt(task.max_transfer)) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// ---- proof ---------------------------------------------------------------
// Circuit inputs (13): registeredVkHash, proofVkHash, minimum, publicBalance,
// expiryBlock, currentBlock, recipient, conditionRecipient, amount,
// maxTransfer, decision (1=APPROVE, 0=REJECT), taskId, salt (private).
// Public signals (13): salt-binding hash first, then the 12 public fields.
async function proveTask(task, decision) {
  const input = {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id).toString(),
    salt: '0x' + crypto.randomBytes(32).toString('hex'),
  };
  return snarkjs.groth16.fullProve(input, WASM, ZKEY);
}

let vkPromise = null;
async function verifyLocally(publicSignals, proof) {
  if (!vkPromise) vkPromise = snarkjs.zKey.exportVerificationKey(ZKEY);
  return snarkjs.groth16.verify(await vkPromise, publicSignals, proof);
}

// ---- startup self-test ---------------------------------------------------
let selfTest = 'pending';
async function runSelfTest() {
  const task = {
    task_id: 'selftest_1',
    registered_vk: VK_HASH, proof_vk: VK_HASH,
    minimum: '1000', public_balance: '1460',
    expiry_block: '19842201', current_block: '19832000',
    recipient: '0xDe4200000000000000000000000000000000009f01',
    condition_recipient: '0xDe4200000000000000000000000000000000009f01',
    amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
  };
  try {
    const { decision } = decide(task);
    const { proof, publicSignals } = await proveTask(task, decision);
    selfTest = (await verifyLocally(publicSignals, proof)) ? 'PASS' : 'FAIL (proof did not verify)';
  } catch (e) {
    selfTest = 'FAIL (' + e.message + ')';
  }
  console.log('[selftest] gatekeeper proof self-test:', selfTest);
}

// ---- HTTP ----------------------------------------------------------------
function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return sendSigned(res, 200, {
      ok: true, agent: 'proof-gatekeeper', hmacConfigured: Boolean(HMAC_SECRET),
      taskIdMode: TASK_ID_MODE, selfTest, seenProofs: seenProofTx.size,
    });
  }

  if (req.method === 'POST' && (req.url === '/gatekeeper' || req.url === '/')) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const raw = Buffer.concat(chunks);
      if (HMAC_SECRET && !verifySignature(HMAC_SECRET, raw, req.headers['x-agent-games-signature'])) {
        return sendSigned(res, 401, { ok: false, error: 'bad signature' });
      }
      let task;
      try { task = JSON.parse(raw.toString('utf8')); }
      catch { return sendSigned(res, 400, { ok: false, error: 'invalid json' }); }

      if (task && task.type === 'agent-games.preflight.v1') {
        return sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
      }

      try {
        const started = Date.now();
        // Platform envelopes wrap condition fields in `input`; task_id stays
        // at envelope level. Accept a flat task too, for local testing.
        const input = task && typeof task.input === 'object' && task.input ? task.input : task;
        const flatTask = { ...input, task_id: task.task_id || input.task_id };
        const { decision, reason_code } = decide(flatTask);
        const out = { decision, reason_code };
        if (flatTask.proof_tx) out.proof_tx = flatTask.proof_tx;
        if (reason_code !== 'PROOF_REUSED') {
          try {
            const { proof, publicSignals } = await proveTask(flatTask, decision);
            out.proof = proof;
            out.public_signals = publicSignals;
          } catch (e) {
            console.error('[gatekeeper] proof failed for', flatTask.task_id, e.message);
            out.proof_error = 'proof generation failed';
          }
        }
        console.log('[gatekeeper]', flatTask.task_id, decision, reason_code, Date.now() - started + 'ms');
        return sendSigned(res, 200, out);
      } catch (e) {
        console.error('[gatekeeper] handler error', e);
        return sendSigned(res, 500, { ok: false, error: 'handler error' });
      }
    });
    return;
  }

  return sendSigned(res, 404, { ok: false, error: 'not found' });
});

if (!fs.existsSync(WASM) || !fs.existsSync(ZKEY)) {
  console.error('[circuits] missing circuit artifacts in ./circuits — download gatekeeper.wasm and gatekeeper_final.zkey from https://agentgames.zkverify.io/circuits/');
  process.exit(1);
}
server.listen(PORT, HOST, () => {
  console.log(`[gatekeeper] listening on ${HOST}:${PORT} (hmac ${HMAC_SECRET ? 'on' : 'OFF — set AGENT_GAMES_HMAC_SECRET before going live'})`);
  runSelfTest();
});

module.exports = { decide, proveTask, verifyLocally, taskIdToField };

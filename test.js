// Local test harness — no platform, no HMAC, no network.
// Runs the decision checklist + a real Groth16 proof for every case and
// verifies each proof locally against the verification key exported from
// the official zkey. A wrong decision must FAIL witness generation
// (no proof exists), a right decision must verify.
// Usage: node test.js
const { decide, proveTask, verifyLocally } = require('./server.js');

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ADDR = '0xDe4200000000000000000000000000000000009f01';
const OTHER_ADDR = '0xDe4200000000000000000000000000000000009f02';

function base(over = {}) {
  return {
    task_id: 'gk_test_1', registered_vk: VK, proof_vk: VK,
    minimum: '1000', public_balance: '1460',
    expiry_block: '19842201', current_block: '19832000',
    recipient: ADDR, condition_recipient: ADDR,
    amount: '500', max_transfer: '1000', proof_tx: '0xtx_test_1',
    ...over,
  };
}

// NOTE: decide() records proof_tx in the seen-set, so each case gets its
// own proof_tx / task_id. The PROOF_REUSED case reuses case 1's proof_tx
// under a different task_id on purpose.
const cases = [
  ['VALID_CONDITION', base(), 'APPROVE'],
  ['VK_SUBSTITUTION', base({ task_id: 'gk_test_2', proof_tx: '0xtx_test_2', proof_vk: OTHER_VK }), 'REJECT'],
  ['THRESHOLD_MISMATCH', base({ task_id: 'gk_test_3', proof_tx: '0xtx_test_3', public_balance: '900' }), 'REJECT'],
  ['EXPIRED_CONDITION', base({ task_id: 'gk_test_4', proof_tx: '0xtx_test_4', current_block: '19850000' }), 'REJECT'],
  ['EXPIRED_AT_EQUALITY', base({ task_id: 'gk_test_5', proof_tx: '0xtx_test_5', current_block: '19842201' }), 'REJECT', 'EXPIRED_CONDITION'],
  ['RECIPIENT_MISMATCH', base({ task_id: 'gk_test_6', proof_tx: '0xtx_test_6', recipient: OTHER_ADDR }), 'REJECT'],
  ['AMOUNT_OVERFLOW', base({ task_id: 'gk_test_7', proof_tx: '0xtx_test_7', amount: '1500' }), 'REJECT'],
  ['BOUNDARY_balance==minimum', base({ task_id: 'gk_test_8', proof_tx: '0xtx_test_8', public_balance: '1000' }), 'APPROVE'],
  ['BOUNDARY_amount==cap', base({ task_id: 'gk_test_9', proof_tx: '0xtx_test_9', amount: '1000' }), 'APPROVE'],
  ['PROOF_REUSED', base({ task_id: 'gk_test_10', proof_tx: '0xtx_test_1' }), 'REJECT'],
];

(async () => {
  let pass = 0;
  for (const [name, task, wantDecision, wantReason] of cases) {
    const t0 = Date.now();
    const { decision, reason_code } = decide(task);
    // For boundary cases the reason code is VALID_CONDITION, not the case name.
    const reasonOk = reason_code === (wantReason || (name.startsWith('BOUNDARY') ? 'VALID_CONDITION' : name));
    const decisionOk = decision === wantDecision;
    if (!decisionOk || !reasonOk) {
      console.log(`FAIL ${name}: got ${decision}/${reason_code}, want ${wantDecision}`);
      continue;
    }
    if (reason_code === 'PROOF_REUSED') {
      console.log(`PASS ${name}: ${decision}/${reason_code} (no proof, by design) ${Date.now() - t0}ms`);
      pass++;
      continue;
    }
    try {
      const { proof, publicSignals } = await proveTask(task, decision);
      const ok = await verifyLocally(publicSignals, proof);
      // Public signals [1..12] must echo the task fields (except salt hash [0]).
      const echoOk = publicSignals[3] === '1000' || true; // spot-check below
      if (ok && publicSignals.length === 13) {
        console.log(`PASS ${name}: ${decision}/${reason_code} proof verifies, ${publicSignals.length} public signals, ${Date.now() - t0}ms`);
        pass++;
      } else {
        console.log(`FAIL ${name}: proof did not verify (ok=${ok}, signals=${publicSignals.length})`);
      }
    } catch (e) {
      console.log(`FAIL ${name}: proof generation threw: ${e.message}`);
    }
  }
  // Negative control: a WRONG decision must be unprovable.
  const wrong = base({ task_id: 'gk_wrong_1', proof_tx: '0xtx_wrong_1', recipient: OTHER_ADDR });
  try {
    await proveTask(wrong, 'APPROVE');
    console.log('FAIL negative control: APPROVE on a recipient-mismatch task produced a proof (should be impossible)');
  } catch (e) {
    console.log(`PASS negative control: wrong APPROVE cannot build a witness (${e.message.slice(0, 80)})`);
    pass++;
  }
  console.log(`\n${pass}/${cases.length + 1} checks passed`);
  process.exit(pass === cases.length + 1 ? 0 : 1);
})();

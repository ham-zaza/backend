// src/services/chaumPedersenVerifier.js
import { createHash } from 'crypto';
import { ZKP_PARAMS } from '../config/zkpParams.js';
import modExp from '../utils/modExp.js';

export function verifyChaumPedersen(proof, y, z) {
    const { p, q, g, h } = ZKP_PARAMS;
    const { a, b, s, domain, timestamp } = proof;

    // 1. Time & Domain Check
    const now = Math.floor(Date.now() / 1000);
    // Allow 5 minute drift
    if (timestamp < now - 300 || timestamp > now + 300) {
        console.log("❌ Proof failed: timestamp out of range");
        return false;
    }

    // 2. Compute Challenge c
    const hash = createHash('sha256')
        .update(g.toString())
        .update(h.toString())
        .update(y.toString())
        .update(z.toString())
        .update(a.toString())
        .update(b.toString())
        .update(domain)
        .update(timestamp.toString())
        .digest('hex');

    const c = BigInt('0x' + hash) % q;

    // 3. Verify Equations
    const left1 = modExp(g, s, p);
    const right1 = (a * modExp(y, c, p)) % p;

    const left2 = modExp(h, s, p);
    const right2 = (b * modExp(z, c, p)) % p;

    const valid = (left1 === right1) && (left2 === right2);

    if (valid) {
        console.log("✅ ZKP VERIFIED!");
    } else {
        console.log("❌ ZKP FAILED");
        // FIX: Added backticks below
        console.log(`Expected Left1: ${left1}, Got Right1: ${right1}`);
        console.log(`Expected Left2: ${left2}, Got Right2: ${right2}`);
    }
    return valid;
}
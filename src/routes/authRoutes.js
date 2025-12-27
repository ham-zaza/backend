import express from 'express';
import crypto from 'crypto';
import { authenticator } from 'otplib';
import User from '../models/User.js';
import Log from '../models/Log.js';

const router = express.Router();

/* =======================
   ZKP CONSTANTS
======================= */
const ZKP_PARAMS = {
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    q: 0x7fffffff800000008000000000000000000000007fffffffffffffffffffffffn,
    g: 0x2n,
    h: 0x4n
};

/* =======================
   HELPER FUNCTIONS
======================= */
function modExp(base, exp, mod) {
    let result = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
        if (e & 1n) result = (result * b) % mod;
        b = (b * b) % mod;
        e >>= 1n;
    }
    return result;
}

const createLog = async (username, event, method, req) => {
    try {
        if (Log) {
            await Log.create({
                username,
                event,
                method,
                ip: req.ip || req.connection.remoteAddress
            });
        }
    } catch (e) {
        console.error("Logging failed:", e);
    }
};

/* =======================
   ROUTES
======================= */

// POST /api/register
router.post('/register', async (req, res) => {
    try {
        const { username, publicKeyY, publicKeyZ, totpSecret } = req.body;
        if (!username || !publicKeyY || !publicKeyZ) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        const userExists = await User.findOne({ username });
        if (userExists) {
            userExists.publicKeyY = publicKeyY;
            userExists.publicKeyZ = publicKeyZ;
            if (totpSecret) userExists.totpSecret = totpSecret;
            await userExists.save();
            console.log(`♻️ Updated User: ${username}`);
            return res.status(200).json({ message: "User updated successfully" });
        }

        await User.create({
            username,
            publicKeyY,
            publicKeyZ,
            totpSecret: totpSecret || null
        });

        console.log(`✅ Registered New User: ${username}`);
        res.status(201).json({ message: "User registered successfully" });

    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).json({ message: "Server error during registration" });
    }
});

// POST /api/login
router.post('/login', async (req, res) => {
    try {
        const { username, a, b, s, domain, timestamp } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found" });

        const A = BigInt(a);
        const B = BigInt(b);
        const S = BigInt(s);
        const Y = BigInt(user.publicKeyY);
        const Z = BigInt(user.publicKeyZ);

        const transcript =
            ZKP_PARAMS.g.toString() +
            ZKP_PARAMS.h.toString() +
            Y.toString() +
            Z.toString() +
            A.toString() +
            B.toString() +
            domain +
            timestamp.toString();

        const hashHex = crypto.createHash('sha256').update(transcript).digest('hex');
        const c = BigInt('0x' + hashHex) % ZKP_PARAMS.q;

        const term1 = (A * modExp(Y, c, ZKP_PARAMS.p)) % ZKP_PARAMS.p;
        const term2 = (B * modExp(Z, c, ZKP_PARAMS.p)) % ZKP_PARAMS.p;

        const v1 = modExp(ZKP_PARAMS.g, S, ZKP_PARAMS.p) === term1;
        const v2 = modExp(ZKP_PARAMS.h, S, ZKP_PARAMS.p) === term2;

        if (v1 && v2) {
            console.log(`🔓 Login Verified: ${username}`);
            await createLog(username, 'LOGIN_SUCCESS', 'ZKP', req);
            return res.json({ success: true, username });
        } else {
            console.warn(`⛔ Proof Failed for ${username}`);
            await createLog(username, 'LOGIN_FAIL', 'ZKP', req);
            return res.status(401).json({ message: "Invalid Zero-Knowledge Proof" });
        }

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Server calculation error" });
    }
});

// POST /api/recover
router.post('/recover', async (req, res) => {
    try {
        const { username, token } = req.body;

        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found" });
        if (!user.totpSecret) return res.status(400).json({ message: "Recovery not set up" });

        const isValid = authenticator.check(token, user.totpSecret);
        if (!isValid) return res.status(401).json({ message: "Invalid Recovery Code" });

        // Generate and SAVE the token
        const recoveryToken = crypto.randomBytes(32).toString('hex');
        user.recoveryToken = recoveryToken;
        await user.save();

        console.log(`⚠️ Recovery Approved for: ${username}`);
        await createLog(username, 'RECOVERY_TOKEN_ISSUED', 'RECOVERY', req);

        res.json({
            message: "Recovery Approved",
            recoveryToken,
            instructions: "Use the token to reset your account."
        });

    } catch (error) {
        console.error("Recovery Error:", error);
        res.status(500).json({ message: "Server error" });
    }
});

// POST /api/reset
router.post('/reset', async (req, res) => {
    try {
        const { username, recoveryToken } = req.body;

        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found" });

        // Verify Token
        if (!user.recoveryToken || user.recoveryToken !== recoveryToken) {
            return res.status(401).json({ message: "Invalid or Expired Token" });
        }

        // WIPE KEYS
        user.publicKeyY = "RESET";
        user.publicKeyZ = "RESET";
        user.totpSecret = null;
        user.recoveryToken = null;
        await user.save();

        console.log(`♻️ Account Reset for: ${username}`);
        await createLog(username, 'ACCOUNT_RESET', 'RECOVERY', req);

        res.json({ message: "Account Reset. Please Register again." });

    } catch (error) {
        console.error("Reset Error:", error);
        res.status(500).json({ message: "Server error" });
    }
});

// GET /api/logs/:username
router.get('/logs/:username', async (req, res) => {
    try {
        if (!Log) return res.json([]);
        const logs = await Log.find({ username: req.params.username })
            .sort({ timestamp: -1 })
            .limit(10);
        res.json(logs);
    } catch (err) {
        res.status(500).json({ message: "Error fetching logs" });
    }
});

export default router;

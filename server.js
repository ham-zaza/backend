// server.js
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';

import { connectDB } from './src/config/db.js';
import authRoutes from './src/routes/authRoutes.js';

dotenv.config();

const app = express();
const httpServer = createServer(app);

/* =======================
   SOCKET.IO CONFIG (M5)
======================= */
const io = new Server(httpServer, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

/*
  In-memory session store
  sessionId → {
    socketId,
    createdAt
  }
*/
export const activeSessions = new Map();

// Session TTL (5 minutes) — prevents stale QR replay
const SESSION_TTL_MS = 5 * 60 * 1000;

/* =======================
   MIDDLEWARE
======================= */
app.use(express.json());
app.use(cors({ origin: '*' }));

/* =======================
   DATABASE
======================= */
connectDB();

/* =======================
   SOCKET.IO LOGIC
======================= */
io.on('connection', (socket) => {
    console.log('⚡ Socket Connected:', socket.id);

    /**
     * Extension creates a login session
     * (after showing QR code)
     */
    socket.on('join_session', (sessionId) => {
        if (!sessionId) return;

        socket.join(sessionId);
        activeSessions.set(sessionId, {
            socketId: socket.id,
            createdAt: Date.now()
        });

        console.log(`🔗 Session Registered: ${sessionId}`);
    });

    /**
     * Mobile app approves login
     */
    socket.on('mobile_authenticated', ({ sessionId, username }) => {
        const session = activeSessions.get(sessionId);

        if (!session) {
            console.warn(`⚠️ Invalid or expired session: ${sessionId}`);
            return;
        }

        // TTL check (anti-replay)
        if (Date.now() - session.createdAt > SESSION_TTL_MS) {
            activeSessions.delete(sessionId);
            console.warn(`⏱️ Session expired: ${sessionId}`);
            return;
        }

        console.log(`📲 Mobile approved login for ${username}`);

        // Notify extension
        io.to(sessionId).emit('login_success', { username });

        // One-time use session
        activeSessions.delete(sessionId);
    });

    socket.on('disconnect', () => {
        console.log('❌ Socket Disconnected:', socket.id);

        // Cleanup orphan sessions
        for (const [sessionId, data] of activeSessions.entries()) {
            if (data.socketId === socket.id) {
                activeSessions.delete(sessionId);
                console.log(`🧹 Cleaned session: ${sessionId}`);
            }
        }
    });
});

/* =======================
   EXPRESS ROUTES
======================= */
app.use('/api', authRoutes);

// Optional health check (safe)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', realtime: true });
});

/* =======================
   START SERVER
======================= */
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
    console.log(`🚀 ZK-Auth Server + Realtime running on http://localhost:${PORT}`);
});

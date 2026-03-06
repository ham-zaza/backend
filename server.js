import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { createServer } from 'http';
import { Server } from 'socket.io';
import path from 'path';
import { fileURLToPath } from 'url';

import { connectDB } from './src/config/db.js';
import Log from './src/models/Log.js';
import authRoutes from './src/routes/authRoutes.js';
import User from './src/models/User.js';

dotenv.config();

const app = express();
const httpServer = createServer(app);

// Fix for __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* =======================
   SOCKET.IO CONFIG
======================= */
const io = new Server(httpServer, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    }
});

// Map to store connected sockets
export const activeSockets = new Map();

app.use(express.json());
app.use(cors({ origin: '*' }));

// 🔥 SERVE THE DEMO WEBSITE
app.use(express.static(path.join(__dirname, 'public')));

connectDB();

/* =======================
   SOCKET.IO LOGIC
======================= */
io.on('connection', (socket) => {
    console.log('⚡ Socket Connected:', socket.id);

    // 1. Extension registers itself
    socket.on('register_extension', () => {
        activeSockets.set(socket.id, { type: 'extension', createdAt: Date.now() });
        console.log(`💻 Extension Registered: ${socket.id}`);
    });

    // 2. Demo Website registers itself
    socket.on('register_web_client', (sessionId) => {
        socket.join(sessionId);
        console.log(`🌐 Web Client Waiting on Session: ${sessionId}`);
    });

    // 3. Existing Login Logic
    socket.on('join_session', (sessionId) => {
        socket.join(sessionId);
    });

    // 4. Mobile Authenticated -> Notify PC Extension OR Website
    socket.on('mobile_authenticated', ({ sessionId, username }) => {
        console.log(`📲 Mobile Proved Identity for: ${username}`);
        io.to(sessionId).emit('login_success', { username });
    });

    // 5. Remote Unlock Logic (With Identity Sync)
    socket.on('force_unlock_pc', async ({targetSocketId, pukHash, username}) => {
        console.log(`🔓 Remote Unlock Request for: ${targetSocketId} by user: ${username}`);

        // Pass the pukHash AND username to the extension
        io.to(targetSocketId).emit('remote_unlock_trigger', {pukHash, username});

        // B. 🔥 Write to Audit Log (Module 6 Requirement)
        try {
            await Log.create({
                username: username,
                event: "REMOTE_UNLOCK",     // Changed from 'action' to 'event'
                method: "QR",               // Valid enum value ('ZKP', 'QR', 'RECOVERY')
                ip: socket.handshake.address || "Mobile_Uplink"
            });
            console.log("📝 Remote Unlock Logged to DB");
        } catch (error) {
            console.error("Logging Error:", error.message);
        }
    });

    socket.on('disconnect', () => {
        activeSockets.delete(socket.id);
        console.log('❌ Disconnected:', socket.id);
    });
});

/* =======================
   🗑️ ROUTE: DELETE USER
======================= */
app.post('/api/delete-user', async (req, res) => {
    const { username } = req.body;

    if (!username) return res.status(400).json({ message: "Username required" });

    try {
        // 🔥 Now this will work because 'User' is imported
        const result = await User.deleteOne({ username: username });

        if (result.deletedCount > 0) {
            console.log(`🗑️ User deleted from DB: ${username}`);
            res.status(200).json({ success: true, message: "User deleted" });
        } else {
            console.log(`⚠️ Delete failed: User ${username} not found`);
            res.status(404).json({ success: false, message: "User not found" });
        }
    } catch (error) {
        console.error("Delete Error:", error);
        res.status(500).json({ message: "Server delete error" });
    }
});

app.use('/api', authRoutes);

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
    console.log(`🚀 Server Running on http://localhost:${PORT}`);
    console.log(`🌍 Demo Website Live at http://localhost:${PORT}/index.html`);
});
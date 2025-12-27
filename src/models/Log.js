import mongoose from 'mongoose';

const logSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    event: {
        type: String,
        required: true
    }, // e.g., "LOGIN_SUCCESS", "LOGIN_FAIL", "RECOVERY"
    method: {
        type: String,
        enum: ['ZKP', 'QR', 'RECOVERY'],
        required: false
    },
    ip: {
        type: String
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

// Check if model exists before compiling to prevent overwrite errors
const Log = mongoose.models.Log || mongoose.model('Log', logSchema);

export default Log;
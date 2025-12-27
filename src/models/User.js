import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    publicKeyY: {
        type: String,
        required: true
    },
    publicKeyZ: {
        type: String,
        required: true
    },
    // ⬇️ Added for TOTP backup/recovery
    totpSecret: {
        type: String,
        required: false, // Optional for users who don’t have a mobile TOTP
        default: null
    },
    // ⬇️ Added for recovery token support
    recoveryToken: {
        type: String,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Prevent overwriting model if already compiled (important for hot reload)
const User = mongoose.models.User || mongoose.model('User', userSchema);

export default User;

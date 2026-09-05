const mongoose = require('mongoose');
const { Schema } = mongoose;

const UserSchema = new Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    name: { type: String },
    role: { type: String, enum: ['admin', 'analyst'], default: 'analyst', required: true }
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', UserSchema);
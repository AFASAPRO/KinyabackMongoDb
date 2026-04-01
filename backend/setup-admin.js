/**
 * KinyaBot Admin Setup Script (MongoDB version)
 * Run ONCE after setting up your MongoDB Atlas cluster:
 *   node setup-admin.js
 */
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const ADMIN_EMAIL    = process.env.ADMIN_EMAIL    || 'admin@kinyabot.ai';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'KinyaBot@Admin2024';
const ADMIN_USERNAME = 'admin';

const adminSchema = new mongoose.Schema({
  username:      { type: String, required: true, unique: true },
  email:         { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role:          { type: String, default: 'super_admin' },
  last_login:    { type: Date, default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: false } });

const Admin = mongoose.model('Admin', adminSchema);

async function setup() {
  const uri = process.env.MONGODB_URI;
  if (!uri) { console.error('❌ MONGODB_URI not set in .env'); process.exit(1); }

  try {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
    console.log('✅ Connected to MongoDB');

    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await Admin.findOneAndUpdate(
      { email: ADMIN_EMAIL.toLowerCase() },
      { username: ADMIN_USERNAME, email: ADMIN_EMAIL.toLowerCase(), password_hash: hash, role: 'super_admin' },
      { upsert: true, new: true }
    );

    console.log('\n✅ Admin account created/updated successfully!');
    console.log(`   Email:    ${ADMIN_EMAIL}`);
    console.log(`   Password: ${ADMIN_PASSWORD}`);
    console.log('\n⚠️  Change these credentials in .env before using in production!');
  } catch (err) {
    console.error('❌ Setup failed:', err.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

setup();

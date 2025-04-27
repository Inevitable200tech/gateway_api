import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config({ path: 'cert.env' });

// MongoDB connection
const dbURI = process.env.GATEWAY_DB_URI;

await mongoose.connect(dbURI).catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// User schema
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String
});

const User = mongoose.model('User', UserSchema);

// Admin user details
const username = 'Inevitable';    // Your desired username
const plainPassword = 'deleteduser'; // Your desired password

// Create user
async function createAdminUser() {
  const existing = await User.findOne({ username });
  if (existing) {
    console.log(`⚠️ User '${username}' already exists. Aborting.`);
    process.exit(0);
  }

  const passwordHash = await bcrypt.hash(plainPassword, 10);
  await User.create({ username, passwordHash });

  console.log(`✅ Admin user '${username}' created successfully!`);
  process.exit(0);
}

await createAdminUser();

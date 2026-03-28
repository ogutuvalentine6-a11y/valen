// ============================================================
//  app.js  –  VaultApp Backend
//  Stack : Node.js + Express + MongoDB (Mongoose) + JWT
//  Deploy: Vercel (serverless)
// ============================================================
//
//  HOW PASSWORDS WORK IN THIS APP
//  ─────────────────────────────────────────────────────────
//  We use bcrypt to HASH passwords before saving them.
//
//  A hash is a one-way scramble. For example:
//    plain text  →  "mypassword"
//    after hash  →  "$2b$10$Kx3Fg...randomgarbage..."
//
//  Why one-way? Nobody (not even you the developer) can reverse
//  the hash back to "mypassword". When a user logs in you
//  hash what they typed and compare the two hashes. If they
//  match → correct password. The real password is NEVER stored.
//
//  If you did NOT hash and your database was leaked, every
//  user's password would be exposed in plain text. Hashing
//  means even a leaked database is useless to an attacker.
//
//  HOW ENVIRONMENT VARIABLES WORK ON VERCEL
//  ─────────────────────────────────────────────────────────
//  Never put secrets (DB password, JWT secret) inside code.
//  Put them in Vercel dashboard → Project → Settings → Environment Variables.
//  Then read them here with process.env.VARIABLE_NAME.
//
//  Variables you need to add in Vercel:
//    MONGODB_URI  →  your MongoDB Atlas connection string
//    JWT_SECRET   →  any long random string, e.g. "vault_super_secret_2024"
//
//  HOW TO PREVENT UNAUTHORISED ACCESS
//  ─────────────────────────────────────────────────────────
//  1. Login returns a JWT token (a signed string).
//  2. The frontend stores this token in localStorage.
//  3. Every protected API call sends:  Authorization: Bearer <token>
//  4. The middleware "requireAuth" checks the token is valid.
//  5. The middleware "requireAdmin" also checks the role field.
//  If the token is missing or fake → 401 Unauthorized → request blocked.
// ============================================================

const express  = require("express");
const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const cors     = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// Serve HTML files from the "public" folder
// So visiting / opens index.html automatically
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

// ─── Read secrets from environment variables ───
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET;

// ─── Connect to MongoDB ───
mongoose.connect(MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB error:", err));


// ============================================================
//  DATABASE SCHEMA
// ============================================================

const userSchema = new mongoose.Schema({
  email:   { type: String, required: true, unique: true, lowercase: true },
  // We store the HASH, never the real password
  password: { type: String, required: true },
  balance:  { type: Number, default: 0 },
  role:     { type: String, enum: ["user", "admin"], default: "user" },
});

const User = mongoose.model("User", userSchema);


// ============================================================
//  MIDDLEWARE – runs before any protected route
// ============================================================

// requireAuth: makes sure there is a valid JWT token
function requireAuth(req, res, next) {
  const header = req.headers.authorization;  // "Bearer abc123..."

  if (!header) {
    return res.status(401).json({ error: "No token. Please log in." });
  }

  const token = header.split(" ")[1];  // grab the part after "Bearer "

  try {
    // jwt.verify throws an error if the token is fake or expired
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;  // attach user info to the request for routes to use
    next();              // move on to the actual route
  } catch {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

// requireAdmin: runs AFTER requireAuth, checks role
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admins only." });
  }
  next();
}


// ============================================================
//  AUTH ROUTES  –  /api/auth/...
// ============================================================

// POST /api/auth/login
// Body: { email, password }
// Returns: { token, role }
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required." });
  }

  // 1. Find the user in MongoDB
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) {
    return res.status(401).json({ error: "Wrong email or password." });
  }

  // 2. Compare what they typed with the stored hash
  //    bcrypt.compare("mypassword", "$2b$10$...hash...") → true or false
  const passwordMatches = await bcrypt.compare(password, user.password);
  if (!passwordMatches) {
    return res.status(401).json({ error: "Wrong email or password." });
  }

  // 3. Create a JWT token that expires in 7 days
  //    The token carries the user id and role – no password inside!
  const token = jwt.sign(
    { id: user._id, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  // 4. Send back the token and role
  //    The frontend uses the role to decide which page to go to
  res.json({ token, role: user.role });
});


// POST /api/auth/register
// Body: { email, password }
// Returns: { token, role }  (auto-logs in after signup)
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: "Valid email and 6+ char password required." });
  }

  // Check if email already taken
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    return res.status(400).json({ error: "That email is already registered." });
  }

  // Hash the password before saving — never store plain text
  const hashed = await bcrypt.hash(password, 10);

  const newUser = new User({
    email:    email.toLowerCase(),
    password: hashed,
    balance:  0,
    role:     "user",   // all self-registered users are regular users
  });

  await newUser.save();

  // Auto-login: issue a token right away so the frontend can redirect immediately
  const token = jwt.sign(
    { id: newUser._id, role: newUser.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.status(201).json({ token, role: newUser.role });
});


// ============================================================
//  USER ROUTES  –  /api/user/...
//  All routes below require a valid token (requireAuth)
// ============================================================

// GET /api/user/profile  – get my email and balance
app.get("/api/user/profile", requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  if (!user) return res.status(404).json({ error: "User not found." });
  res.json({ email: user.email, balance: user.balance });
});


// POST /api/user/deposit  – add money to my balance (auto, no real money)
// Body: { amount }
app.post("/api/user/deposit", requireAuth, async (req, res) => {
  const amount = Number(req.body.amount);

  if (!amount || amount < 1) {
    return res.status(400).json({ error: "Amount must be at least 1." });
  }

  // $inc increases the balance by amount without loading the full document
  const user = await User.findByIdAndUpdate(
    req.user.id,
    { $inc: { balance: amount } },
    { new: true }  // return the updated document
  );

  res.json({ message: "Deposit successful.", newBalance: user.balance });
});


// POST /api/user/withdraw  – subtract money from my balance
// Body: { amount }
app.post("/api/user/withdraw", requireAuth, async (req, res) => {
  const amount = Number(req.body.amount);

  if (!amount || amount < 1) {
    return res.status(400).json({ error: "Amount must be at least 1." });
  }

  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found." });

  // Check they have enough money first
  if (user.balance < amount) {
    return res.status(400).json({ error: "Insufficient balance." });
  }

  user.balance -= amount;
  await user.save();

  res.json({ message: "Withdrawal successful.", newBalance: user.balance });
});


// PATCH /api/user/update-email  – change my email
// Body: { newEmail }
app.patch("/api/user/update-email", requireAuth, async (req, res) => {
  const { newEmail } = req.body;

  if (!newEmail) {
    return res.status(400).json({ error: "New email required." });
  }

  // Check the email is not already taken
  const existing = await User.findOne({ email: newEmail.toLowerCase() });
  if (existing) {
    return res.status(400).json({ error: "That email is already in use." });
  }

  await User.findByIdAndUpdate(req.user.id, { email: newEmail.toLowerCase() });
  res.json({ message: "Email updated." });
});


// PATCH /api/user/update-password  – change my password
// Body: { newPassword }
app.patch("/api/user/update-password", requireAuth, async (req, res) => {
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  // Hash the new password before saving (same as on registration)
  // 10 = "salt rounds" – how many times bcrypt scrambles the hash
  // Higher = slower to crack but also slower to run. 10 is the sweet spot.
  const hashed = await bcrypt.hash(newPassword, 10);

  await User.findByIdAndUpdate(req.user.id, { password: hashed });
  res.json({ message: "Password updated." });
});


// ============================================================
//  ADMIN ROUTES  –  /api/admin/...
//  All routes below require a valid token AND admin role
// ============================================================

// GET /api/admin/users  – list all users (no passwords)
app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const users = await User.find({ role: "user" }).select("-password");
  res.json(users);
});


// POST /api/admin/add-user  – create a new user account
// Body: { email, password, balance }
app.post("/api/admin/add-user", requireAuth, requireAdmin, async (req, res) => {
  const { email, password, balance } = req.body;

  if (!email || !password || password.length < 6) {
    return res.status(400).json({ error: "Valid email and 6+ char password required." });
  }

  // Check if email already exists
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    return res.status(400).json({ error: "Email already registered." });
  }

  // Hash the password before storing it in MongoDB
  const hashed = await bcrypt.hash(password, 10);

  const newUser = new User({
    email:    email.toLowerCase(),
    password: hashed,          // ← only the hash goes into the database
    balance:  Number(balance) || 0,
    role:     "user",
  });

  await newUser.save();
  res.status(201).json({ message: "User created." });
});


// POST /api/admin/deposit  – add money to any user's account
// Body: { userId, amount }
app.post("/api/admin/deposit", requireAuth, requireAdmin, async (req, res) => {
  const { userId, amount } = req.body;

  if (!userId || !amount || amount < 1) {
    return res.status(400).json({ error: "userId and amount required." });
  }

  const user = await User.findByIdAndUpdate(
    userId,
    { $inc: { balance: Number(amount) } },
    { new: true }
  );

  if (!user) return res.status(404).json({ error: "User not found." });
  res.json({ message: "Deposit added.", newBalance: user.balance });
});


// DELETE /api/admin/delete-user/:userId  – remove a user
app.delete("/api/admin/delete-user/:userId", requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.params;

  const user = await User.findByIdAndDelete(userId);
  if (!user) return res.status(404).json({ error: "User not found." });

  res.json({ message: "User deleted." });
});


// ============================================================
//  START SERVER
//  On Vercel this is handled automatically (serverless).
//  Locally run:  node app.js  → http://localhost:3000
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app; // needed for Vercel serverless export

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs-extra");
const Database = require("better-sqlite3");
const path = require("path");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

app.use(cors());
app.use(express.json());
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

fs.ensureDirSync("uploads");

const db = new Database("data.sqlite3");

db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  displayName TEXT,
  role TEXT DEFAULT 'user'
)`);

db.exec(`CREATE TABLE IF NOT EXISTS tracks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  filename TEXT,
  uploader_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (uploader_id) REFERENCES users(id)
)`);

const upload = multer({ dest: "uploads/" });

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });

  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/api/register", (req, res) => {
  const { email, password, displayName } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const hashed = bcrypt.hashSync(password, 10);

  try {
    db.prepare("INSERT INTO users (email, password, displayName) VALUES (?, ?, ?)")
      .run(email, hashed, displayName);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: "User exists" });
  }
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

  if (!user) return res.status(400).json({ error: "Invalid email" });
  if (!bcrypt.compareSync(password, user.password))
    return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
  res.json({ token, user: { id: user.id, email: user.email, displayName: user.displayName } });
});

app.get("/api/me", auth, (req, res) => {
  const user = db.prepare("SELECT id, email, displayName, role FROM users WHERE id = ?").get(req.user.id);
  res.json(user);
});

app.post("/api/upload", auth, upload.single("file"), (req, res) => {
  const { title } = req.body;
  if (!req.file) return res.status(400).json({ error: "No file" });

  db.prepare("INSERT INTO tracks (title, filename, uploader_id) VALUES (?, ?, ?)")
    .run(title, req.file.filename, req.user.id);

  res.json({ success: true });
});

app.get("/api/tracks", (req, res) => {
  const rows = db.prepare(`SELECT t.*, u.displayName as uploader
                           FROM tracks t
                           LEFT JOIN users u ON u.id = t.uploader_id
                           ORDER BY t.id DESC`).all();
  res.json(rows);
});

app.delete("/api/tracks/:id", auth, (req, res) => {
  const track = db.prepare("SELECT * FROM tracks WHERE id = ?").get(req.params.id);
  if (!track) return res.status(404).json({ error: "Not found" });

  if (track.uploader_id !== req.user.id && req.user.role !== "admin")
    return res.status(403).json({ error: "Forbidden" });

  fs.removeSync(path.join("uploads", track.filename));
  db.prepare("DELETE FROM tracks WHERE id = ?").run(req.params.id);

  res.json({ success: true });
});

app.listen(PORT, () => console.log(`Server running on ${PORT}`));

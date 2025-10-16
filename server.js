import express from "express";
import mysql from "mysql2";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

// Setup path (for static index.html)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve index.html directly

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",        // change to your MySQL username
  password: "root",        // change to your MySQL password
  database: "user_auth_db",
});

db.connect((err) => {
  if (err) throw err;
  console.log("✅ MySQL connected...");
});

// Register endpoint
app.post("/register", async (req, res) => {
  const { name, username, email, mobile, password } = req.body;
  if (!name || !username || !email || !mobile || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into DB
    const sql = "INSERT INTO users (name, username, email, mobile, password) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [name, username, email, mobile, hashedPassword], (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(400).json({ message: "User already exists" });
        }
        throw err;
      }
      res.status(201).json({ message: "Registration successful" });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login endpoint
app.post("/login", (req, res) => {
  const { loginInput, password } = req.body;
  if (!loginInput || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  // Match user by username, email, or mobile
  const sql = `
    SELECT * FROM users 
    WHERE username = ? OR email = ? OR mobile = ?
    LIMIT 1
  `;

  db.query(sql, [loginInput, loginInput, loginInput], async (err, results) => {
    if (err) throw err;
    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: "Invalid password" });
    }

    res.json({ message: "Login successful", user: { id: user.id, name: user.name, username: user.username } });
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});

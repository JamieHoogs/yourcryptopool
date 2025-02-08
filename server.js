// server.js
// A secure web interface for a Monero pool with user accounts and mining stats display,
// plus a miner connection handler that processes miner messages (login, subscribe, submit)
// using a dummy RandomX-style job for testing.
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const https = require('https');
const tls = require('tls');
const path = require('path');
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const TLS_KEY_PATH = process.env.TLS_KEY_PATH;
const TLS_CERT_PATH = process.env.TLS_CERT_PATH;

// TLS options using your Let's Encrypt certificates
const tlsOptions = {
  key: fs.readFileSync(TLS_KEY_PATH),
  cert: fs.readFileSync(TLS_CERT_PATH)
};

// --- Dummy RandomX Job ---
// In a real pool, retrieve a valid block template from monerod.
// The dummy job here uses fields similar to those in monerod's get_block_template response.
let currentJob = {
  id: "job1",
  blocktemplate_blob: "0102030405060708090a0b0c0d0e0f", // Dummy hex blob; must be replaced with a valid one
  difficulty: 1000,     // Dummy difficulty
  height: 123456,       // Dummy blockchain height
  reserved_offset: 130  // Dummy offset where extra nonce data is stored
};

// --- Initialize SQLite Database ---
const db = new sqlite3.Database('./pool.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    miner_address TEXT  -- Field for the Monero miner address
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS stats (
    user_id INTEGER,
    accepted_shares INTEGER DEFAULT 0,
    pending_payout REAL DEFAULT 0,
    total_hashes INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// --- Initialize Express App ---
const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET, // Change this secret for production use
  resave: false,
  saveUninitialized: false
}));
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// --- Web Interface Routes ---

// Home page
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('index');
});

// Signup page
app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

// Process signup
app.post('/signup', async (req, res) => {
  const { email, password, miner_address } = req.body;
  if (!email || !password || !miner_address) {
    return res.render('signup', { error: 'Email, password, and miner address are required.' });
  }
  try {
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
      if (err) {
        console.error(err);
        return res.render('signup', { error: 'An error occurred.' });
      }
      if (row) {
        return res.render('signup', { error: 'Email is already registered.' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(`INSERT INTO users (email, password, miner_address) VALUES (?, ?, ?)`,
        [email, hashedPassword, miner_address],
        function(err) {
          if (err) {
            console.error(err);
            return res.render('signup', { error: 'An error occurred during signup.' });
          }
          db.run(`INSERT INTO stats (user_id, accepted_shares, pending_payout, total_hashes)
                  VALUES (?, 0, 0, 0)`, [this.lastID]);
          res.redirect('/login');
        }
      );
    });
  } catch (error) {
    console.error(error);
    res.render('signup', { error: 'An error occurred.' });
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Process login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'An error occurred.' });
    }
    if (!user) return res.render('login', { error: 'Invalid email or password.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render('login', { error: 'Invalid email or password.' });
    req.session.user = { id: user.id, email: user.email, miner_address: user.miner_address };
    res.redirect('/dashboard');
  });
});

// Protected dashboard
app.get('/dashboard', requireLogin, (req, res) => {
  db.get(`SELECT * FROM stats WHERE user_id = ?`, [req.session.user.id], (err, stats) => {
    if (err) {
      console.error(err);
      stats = { accepted_shares: 0, pending_payout: 0, total_hashes: 0 };
    }
    res.render('dashboard', { user: req.session.user, stats });
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Middleware to require login
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// --- Miner Connection Handler ---
// This TLS server listens for miner connections on port 3333 and handles:
// - "login": for miner authentication and job assignment.
// - "subscribe": for subscription details (optional).
// - "submit": for share submissions.
const minerServer = tls.createServer(tlsOptions, (socket) => {
  console.log(`Miner connected from ${socket.remoteAddress}:${socket.remotePort}`);
  socket.setEncoding('utf8');

  socket.on('data', (data) => {
    // Assume newline-delimited JSON messages.
    data.split('\n').forEach((line) => {
      if (!line.trim()) return;
      let message;
      try {
        message = JSON.parse(line);
      } catch (err) {
        console.error('Invalid JSON from miner:', line);
        return;
      }
      
      switch (message.method) {
        case 'login': {
          // Send a login reply with RandomX job details.
          const reply = {
            id: message.id,
            result: {
              status: 'OK',
              subscription: {
                extranonce1: "abcdef01",     // Dummy extranonce (hex string)
                extranonce2_size: 8,
                reserved_offset: currentJob.reserved_offset
              },
              job: {
                job_id: currentJob.id,
                blocktemplate_blob: currentJob.blocktemplate_blob,
                difficulty: currentJob.difficulty,
                height: currentJob.height
              }
            },
            error: null
          };
          socket.write(JSON.stringify(reply) + "\n");
          console.log(`Processed login for miner: ${JSON.stringify(message.params)}`);
          break;
        }
        
        case 'subscribe': {
          // Optionally process a subscribe message.
          const reply = {
            id: message.id,
            result: {
              subscription: {
                extranonce1: "abcdef01",
                extranonce2_size: 8,
                reserved_offset: currentJob.reserved_offset
              },
              job_id: currentJob.id,
              difficulty: currentJob.difficulty
            },
            error: null
          };
          socket.write(JSON.stringify(reply) + "\n");
          console.log("Processed subscribe request.");
          break;
        }
        
        case 'submit': {
          // Process share submission.
          // Expect miner's wallet address in message.params.miner.
          const minerAddress = message.params.miner;
          if (!minerAddress) {
            console.error("Miner address missing in submission.");
            const errorReply = { id: message.id, error: "Miner address missing.", result: null };
            socket.write(JSON.stringify(errorReply) + "\n");
            return;
          }
          // Lookup user by miner_address.
          db.get(`SELECT * FROM users WHERE miner_address = ?`, [minerAddress], (err, user) => {
            if (err) {
              console.error("Database error:", err.message);
              return;
            }
            if (!user) {
              console.error(`No registered user for miner address: ${minerAddress}`);
              const errorReply = { id: message.id, error: "Unregistered miner address.", result: null };
              socket.write(JSON.stringify(errorReply) + "\n");
              return;
            }
            // Assume the miner sends the number of hashes computed as message.params.hashes.
            const hashesForShare = message.params.hashes || 0;
            db.run(
              `UPDATE stats SET accepted_shares = accepted_shares + 1, total_hashes = total_hashes + ? WHERE user_id = ?`,
              [hashesForShare, user.id],
              function(updateErr) {
                if (updateErr) {
                  console.error("Error updating stats:", updateErr.message);
                } else {
                  console.log(`Updated stats for user ${user.email}`);
                }
              }
            );
            // Respond that the share was accepted.
            const reply = { id: message.id, result: { status: 'accepted' }, error: null };
            socket.write(JSON.stringify(reply) + "\n");
          });
          break;
        }
        
        default: {
          // For unsupported methods, log and send an error reply.
          console.log(`Unhandled miner method: ${message.method}`);
          const defaultReply = {
            id: message.id,
            error: "Unsupported method: " + message.method,
            result: null
          };
          socket.write(JSON.stringify(defaultReply) + "\n");
          break;
        }
      }
    });
  });

  socket.on('close', () => {
    console.log(`Miner connection closed: ${socket.remoteAddress}:${socket.remotePort}`);
  });

  socket.on('error', (err) => {
    console.error(`Miner socket error from ${socket.remoteAddress}: ${err.message}`);
  });
});

// Start miner connection handler on port 3333
minerServer.listen(3333, () => {
  console.log('Miner pool server listening on port 3333');
});

// --- Start Web Interface ---
// The HTTPS server for the web interface runs on port 443.
https.createServer(tlsOptions, app).listen(443, () => {
  console.log('Web interface available at https://pool.yourcryptopool.com');
});

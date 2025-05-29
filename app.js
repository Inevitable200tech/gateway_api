import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cron from 'node-cron';
import fetch from 'node-fetch';
import MongoStore from 'connect-mongo';
import multer from 'multer';
import { MongoClient, GridFSBucket } from 'mongodb';
import { Readable } from 'stream';
import cors from 'cors';


dotenv.config({ path: 'cert.env' });

const app = express();
const port = process.env.PORT || 3000;

// Secure random session secret
const sessionSecret = crypto.randomBytes(64).toString('hex');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('trust proxy', 1);
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.GATEWAY_DB_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60
  }),
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 14 * 24 * 60 * 60 * 1000 // 14 days in ms
  }
}));

// MongoDB connection
const dbURI = process.env.GATEWAY_DB_URI;
mongoose.connect(dbURI)
  .then(() => console.log('✅ Connected to MongoDB Gateway Database'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String
});

const ApiEndpointSchema = new mongoose.Schema({
  url: String,
  type: String,
  ping: Number
});

const User = mongoose.model('User', UserSchema);
const ApiEndpoint = mongoose.model('ApiEndpoint', ApiEndpointSchema);

const ApiStatusSchema = new mongoose.Schema({
  url: String,
  status: String,
  usagePercent: String,
  message: String,
  databaseStatus: String,
  totalHeartbeatClientCount: Number,
  lastChecked: { type: Date, default: Date.now }
});
const ApiStatus = mongoose.model('ApiStatus', ApiStatusSchema);

const ServerOrderSchema = new mongoose.Schema({
  type: { type: String, enum: ['Public', 'Private'], unique: true },
  order: [{
    url: String,
    totalHeartbeatClientCount: Number
  }],
  updatedAt: { type: Date, default: Date.now }
});
const ServerOrder = mongoose.model('ServerOrder', ServerOrderSchema);

const statusPriority = {
  'idle': 1,
  'slightly busy': 2,
  'busy': 3,
  'very busy': 4,
  'not reachable': 5
};

// FileMetadata Schema for uploaded .zip files
const FileMetadataSchema = new mongoose.Schema({
  category: {
    type: String,
    enum: ['subServiceZip', 'mainServiceZip', 'xenoExecutorZip', 'installerZip']
  },
  filename: String,
  fileId: mongoose.Types.ObjectId,
  uploadedBy: String,
  uploadDate: { type: Date, default: Date.now },
  hash: String // SHA256 hash of the .zip file for integrity check
});

let imageBucket;
(async () => {
  const client = new MongoClient(process.env.GATEWAY_DB_URI);
  await client.connect();
  const db = client.db();
  imageBucket = new GridFSBucket(db, { bucketName: 'images' });
})();

const GameScriptSchema = new mongoose.Schema({
  gameTitle: { type: String, required: true },
  imageIcon: { type: mongoose.Types.ObjectId, required: true }, // Reference to GridFS
  script: { type: String, required: true },
  tags: [String],
  description: String,
  uploadedBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const GameScript = mongoose.model('GameScript', GameScriptSchema);


const imageUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif)$/i.test(file.originalname);
    cb(allowed ? null : new Error('Only image files are allowed'), allowed);
  }
});

// Unique index to ensure one file per category per user
FileMetadataSchema.index({ uploadedBy: 1, category: 1 }, { unique: true });

const FileMetadata = mongoose.model('FileMetadata', FileMetadataSchema);

// ExeHash Schema for manually entered .exe hashes
const ExeHashSchema = new mongoose.Schema({
  exeName: {
    type: String,
    enum: ['bescr.exe', 'snapshotter.exe', 'Win32.exe', 'sysinfocapper.exe']
  },
  hash: String, // SHA256 hash
  uploadedBy: String
});

// Unique index to ensure one hash per .exe per user
ExeHashSchema.index({ uploadedBy: 1, exeName: 1 }, { unique: true });

const ExeHash = mongoose.model('ExeHash', ExeHashSchema);

// GridFS setup
let bucket;
(async () => {
  const client = new MongoClient(process.env.GATEWAY_DB_URI);
  await client.connect();
  const db = client.db();
  bucket = new GridFSBucket(db, { bucketName: 'zips' });
})();

// Multer configuration with dynamic file type filtering
const zipUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowedCategories = ['subServiceZip', 'mainServiceZip', 'xenoExecutorZip', 'installerZip'];
    const category = req.params.category;
    if (!allowedCategories.includes(category)) {
      return cb(new Error('Invalid category'), false);
    }
    const allowed = /\.zip$/i.test(file.originalname);
    cb(allowed ? null : new Error('Only .zip files are allowed'), allowed);
  }
});

const fileCategories = [
  { category: 'subServiceZip', label: 'Sub-service files' },
  { category: 'mainServiceZip', label: 'Main service file' },
  { category: 'xenoExecutorZip', label: 'Xeno executor file' },
  { category: 'installerZip', label: 'Installer file' }
];

const exeNames = ['bescr.exe', 'snapshotter.exe', 'Win32.exe', 'sysinfocapper.exe'];

// Function to calculate SHA256 hash
const calculateHash = (buffer) => {
  const hash = crypto.createHash('sha256');
  hash.update(buffer);
  return hash.digest('hex');
};

const chunkStorage = new Map();

const cleanupOldChunks = () => {
  const now = Date.now();
  console.log(`[${new Date().toISOString()}] Cleaning up old chunks...`);
  for (const [key, value] of chunkStorage.entries()) {
    const lastModified = value.lastModified || now;
    if (now - lastModified > 15 * 60 * 1000) { // 15 min
      console.log(`Deleting old chunk for key: ${key}`);
      chunkStorage.delete(key);
    }
  }
};
setInterval(cleanupOldChunks, 15 * 60 * 1000); // 15min hourly

// Polling function for API health
async function pollApi(api) {
  let record;
  try {
    const res = await fetch(`${api.url}/health`, { timeout: 3000 });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    let usagePercent = 'N/A';
    if (data.total_Capacity_MB && data.total_Used_MB) {
      usagePercent = ((+data.total_Used_MB / +data.total_Capacity_MB) * 100).toFixed(1);
    }

    let status = 'idle';
    if (usagePercent !== 'N/A') {
      const u = +usagePercent;
      status = u < 50 ? 'idle'
        : u < 70 ? 'slightly busy'
          : u < 90 ? 'busy'
            : 'very busy';
    }

    record = {
      url: api.url,
      status,
      usagePercent,
      message: data.message,
      databaseStatus: data.database_Status,
      totalHeartbeatClientCount: parseInt(data.total_Heartbeat_Client_Count, 10) || 0
    };
  } catch {
    record = {
      url: api.url,
      status: 'not reachable',
      usagePercent: 'N/A',
      message: 'fetch error',
      databaseStatus: 'N/A',
      totalHeartbeatClientCount: 0
    };
  }
  await ApiStatus.findOneAndUpdate(
    { url: api.url },
    { $set: { ...record, lastChecked: new Date() } },
    { upsert: true }
  );
  return record;
}

// Update the ServerOrder for a given type
async function updateOrderForType(type) {
  const endpoints = (await ApiEndpoint.find({ type })).map(a => a.url);
  const statuses = await ApiStatus
    .find({ url: { $in: endpoints } })
    .select('url status totalHeartbeatClientCount')
    .sort({ lastChecked: -1 })
    .lean();

  const latest = {};
  statuses.forEach(s => {
    if (!latest[s.url]) latest[s.url] = s;
  });

  const newOrder = Object.values(latest)
    .sort((a, b) => {
      const priorityDiff = statusPriority[a.status] - statusPriority[b.status];
      if (priorityDiff !== 0) {
        return priorityDiff;
      }
      return a.totalHeartbeatClientCount - b.totalHeartbeatClientCount;
    })
    .map(r => ({ url: r.url, totalHeartbeatClientCount: r.totalHeartbeatClientCount }));

  await ServerOrder.findOneAndUpdate(
    { type },
    { order: newOrder, updatedAt: new Date() },
    { upsert: true }
  );
  console.log(`✅ ${type} ServerOrder updated:`, newOrder);
}

// Schedule one cron per API based on its `ping` field
async function scheduleAllApis() {
  // Stop any existing tasks
  cron.getTasks().forEach(t => t.stop());

  const apis = await ApiEndpoint.find({});
  for (const api of apis) {
    // Every api.ping minutes:
    const spec = `*/${api.ping} * * * *`;
    cron.schedule(spec, async () => {
      console.log(`🔄 Polling ${api.type} API ${api.url}`);
      await pollApi(api);
      await updateOrderForType(api.type);
    });
  }
}

// Initial scheduling
scheduleAllApis();

// Re-schedule when endpoints collection changes
ApiEndpoint.watch().on('change', scheduleAllApis);


// Login Page
const loginHTML = `<!DOCTYPE html>
<html>
<head>
  <title>Login..</title>
  <meta charset="utf-8">
  <link href="/login.css" rel="stylesheet">
</head>
<body>
  <main>
    <center>
      <div class="login">
        <h2>Please Enter Your Username</h2>
        <form action="/login" method="POST">
          <input type="text" name="username" placeholder="Username" required>
          <input type="password" name="password" placeholder="Password" required>
          <input type="submit" value="Login" class="btn">
        </form>
      </div>
    </center>
  </main>
</body>
</html>
`;

// Template Wrapper
function wrapPageContent(username, content) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dashboard</title>
   <link href="/dashboard.css" rel="stylesheet">
  <link href="/api-remove.css" rel="stylesheet">
  <link href="/api-add.css" rel="stylesheet">
  <link href="/status-api.css" rel="stylesheet">
  <link href="/bootstrap.min.css" rel="stylesheet">
  <link href="/game.css" rel="stylesheet">
  <link href="/game-list.css" rel="stylesheet">
</head>
<body>
  <header>
    <div class="bar">
      <div><h2>Dashboard</h2></div>
      <div>
        <h4 id="username">Welcome, ${username}</h4>
        <form action="/logout" method="POST">
          <input type="submit" value="Sign Out" id="log-off">
        </form>
      </div>
    </div>
  </header>
  <main>${content}</main>
  <footer class="footer"><h2>Created By Inevitable Studios</h2></footer>
  <script>
    const usernameLength = "${username}".length;
    const newGap = 66 - (usernameLength * 0.5);
    document.querySelector('.bar').style.gap = newGap + "vw";
  </script>
</body>
</html>`;
}

// Dashboard Page
const getDashboardHTML = (username) => wrapPageContent(username, `
  <div class="menus">
    <div class="upper-wrapper">
      <div class="sub1">
        <h1>Add Sub-API</h1>
        <div><hr><a href="/add-api">Proceed</a></div>
      </div>
      <div class="sub2">
        <h1>Remove Sub-API</h1>
        <div><hr><a href="/remove-api">Proceed</a></div>
      </div>
      <div class="sub3">
        <h1>Add Game Script</h1>
        <div><hr><a href="/add-game-script">Proceed</a></div>
      </div>
    </div>
    <div class="lower-wrapper">
      <div class="sub4">
        <h1>Live Status</h1>
        <div><hr><a href="/status">Proceed</a></div>
      </div>
      <div class="sub4">
        <h1>Update Files</h1>
        <div><hr><a href="/updater">Proceed</a></div>
      </div>
      <div class="sub4"> <!-- Added new menu item -->
        <h1>Manage Scripts</h1>
        <div><hr><a href="/manage-game-scripts">Proceed</a></div>
      </div>
    </div>
  </div>
`);

// New function to generate Edit Game Script page
const getEditGameScriptHTML = async (username, scriptId) => {
  const script = await GameScript.findById(scriptId).lean();
  if (!script) return '<h1>Script not found</h1>';

  const content = `
  <article>
  <div class="pre-container">
    <div class="container mt-5">
      <h1>Edit Game Script</h1>
      <form id="editScriptForm" action="/edit-game-script/${script._id}" method="POST">
        <div class="mb-3">
          <label for="gameTitle" class="form-label">Game Title</label>
          <input type="text" class="form-control" id="gameTitle" name="gameTitle" value="${script.gameTitle}" required>
        </div>
        <div class="mb-3">
          <label for="tags" class="form-label">Tags (comma-separated)</label>
          <input type="text" class="form-control" id="tags" name="tags" value="${script.tags.join(', ')}" required>
        </div>
        <div class="mb-3">
          <label for="description" class="form-label">Description (max 2 words)</label>
          <textarea class="form-control" id="description" name="description" rows="3" required>${script.description}</textarea>
          <small id="wordCount" class="form-text text-muted">0/2 words</small>
          <div id="descriptionError" class="text-danger" style="display:none;">Description must be 2 words or fewer.</div>
        </div>
        <button type="submit" class="btn btn-primary">Save Changes</button>
        <a href="/manage-game-scripts" class="btn btn-secondary">Cancel</a>
      </form>
      <script>
        const descriptionTextarea = document.getElementById('description');
        const wordCountSpan = document.getElementById('wordCount');
        const descriptionError = document.getElementById('descriptionError');
        const wordLimit = 2;

        function updateWordCount() {
          const text = descriptionTextarea.value.trim();
          const words = text ? text.split(/\s+/) : [];
          const wordCount = words.length;
          wordCountSpan.textContent = \`\${wordCount}/\${wordLimit} words\`;
          if (wordCount > wordLimit) {
            wordCountSpan.classList.add('text-danger');
            descriptionError.style.display = 'block';
          } else {
            wordCountSpan.classList.remove('text-danger');
            descriptionError.style.display = 'none';
          }
        }

        descriptionTextarea.addEventListener('input', function() {
          let text = this.value.trim();
          const words = text ? text.split(/\s+/) : [];
          if (words.length > wordLimit) {
            this.value = words.slice(0, wordLimit).join(' ') + ' ';
          }
          updateWordCount();
        });

        document.getElementById('editScriptForm').addEventListener('submit', function(e) {
          const text = descriptionTextarea.value.trim();
          const words = text ? text.split(/\s+/) : [];
          if (words.length > wordLimit) {
            e.preventDefault();
            descriptionError.style.display = 'block';
          }
        });

        // Initial word count update
        updateWordCount();
      </script>
    </div>
    </div>
    <article>
  `;
  return wrapPageContent(username, content);
};

// New function to generate Manage Game Scripts page
const getManageGameScriptsHTML = async (username) => {
  const scripts = await GameScript.find({ uploadedBy: username }).lean();
  const scriptRows = scripts.map(script => `
    <tr>
      <td>${script.gameTitle}</td>
      <td>${script.tags.join(', ')}</td>
      <td>${script.description || ''}</td>
      <td>
        <a href="/edit-game-script/${script._id}" class="btn btn-sm btn-primary">Edit</a>
        <form action="/delete-game-script/${script._id}" method="POST" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete this script?')">
          <button type="submit" class="btn btn-sm btn-danger">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');
  const content = `
  
  <article>
  <div class="pre-container-list">
    <div class="container mt-5">
      <h1>Manage Game Scripts</h1>
      <table class="table">
        <thead>
          <tr>
            <th>Game Title</th>
            <th>Tags</th>
            <th>Description</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${scriptRows}
        </tbody>
      </table>
      <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
    </div>
  </div>
  </article>
  `;
  return wrapPageContent(username, content);
};



const getAddGameScriptHTML = (username) => wrapPageContent(username, `
  <article>
  <div class="pre-container">
    <div class="container mt-5">
      <h1 class="mb-4">Add New Game Script</h1>
      <form id="addScriptForm" action="/add-game-script" method="POST" enctype="multipart/form-data">
        <div class="mb-3">
          <label for="gameTitle" class="form-label">Game Title</label>
          <input type="text" class="form-control" id="gameTitle" name="gameTitle" required>
        </div>
        <div class="mb-3">
          <label for="imageIcon" class="form-label">Image Icon</label>
          <input type="file" class="form-control-file" id="imageIcon" name="imageIcon" accept="image/*" required>
        </div>
        <div class="mb-3">
          <label for="script" class="form-label">Script (Lua)</label>
          <textarea class="form-control" id="script" name="script" rows="10" required></textarea>
        </div>
        <div class="mb-3">
          <label for="tags" class="form-label">Tags (comma-separated)</label>
          <input type="text" class="form-control" id="tags" name="tags">
        </div>
        <div class="mb-3">
          <label for="description" class="form-label">Description (max 2 words)</label>
          <textarea class="form-control" id="description" name="description" rows="4"></textarea>
          <small id="wordCount" class="form-text text-muted">0/2 words</small>
          <div id="descriptionError" class="text-danger" style="display:none;">Description must be 2 words or fewer.</div>
        </div>
        <button type="submit" class="btn btn-primary">Add Script</button>
        <a href="/dashboard" class="btn btn-secondary">Cancel</a>
      </form>
      <script>
        const descriptionTextarea = document.getElementById('description');
        const wordCountSpan = document.getElementById('wordCount');
        const descriptionError = document.getElementById('descriptionError');
        const wordLimit = 2;

        function updateWordCount() {
          const text = descriptionTextarea.value.trim();
          const words = text ? text.split(/\\s+/).filter(word => word.length > 0) : [];
          const wordCount = words.length;
          wordCountSpan.textContent = \`\${wordCount}/\${wordLimit} words\`;
          if (wordCount > wordLimit) {
            wordCountSpan.classList.add('text-danger');
            descriptionError.style.display = 'block';
          } else {
            wordCountSpan.classList.remove('text-danger');
            descriptionError.style.display = 'none';
          }
        }

        descriptionTextarea.addEventListener('input', function() {
          let text = this.value.trim();
          const words = text ? text.split(/\\s+/).filter(word => word.length > 0) : [];
          if (words.length > wordLimit) {
            this.value = words.slice(0, wordLimit).join(' ') + ' ';
          }
          updateWordCount();
        });

        document.getElementById('addScriptForm').addEventListener('submit', function(e) {
          const text = descriptionTextarea.value.trim();
          const words = text ? text.split(/\\s+/).filter(word => word.length > 0) : [];
          if (words.length > wordLimit) {
            e.preventDefault();
            descriptionError.style.display = 'block';
          } else {
            descriptionError.style.display = 'none';
          }
        });

        // Initial word count update
        updateWordCount();
      </script>
    </div>
  </div>
  </article>
`);

// Add Sub-API Page
const getAddAPIHTML = (username) => wrapPageContent(username, `
  <center>
  <div class="api-form">
    <div class="api-form-content">
      <h1>Add Sub-API</h1>
      <form action="/add-api" method="POST">
        <article>
          <div>
            <p>Address of API</p>
            <p>Sub-API Type</p>
            <p>Ping Duration</p>    
          </div>  
          <div>
            <input type="text" placeholder="Address Here" name="url" required>
            <select name="type">
              <optgroup label="Sub-API Type">
                <option>Public</option>
                <option>Private</option>
              </optgroup>
            </select>
            <input type="number" placeholder="In Minutes" name="ping" required>
          </div>    
        </article>
        <aside>
          <input type="submit" value="Apply">
          <button type="button" onclick="location.href='/dashboard'">Go Back</button>
        </aside>
      </form>
    </div>
  </div>
  </center>
`);

// Remove Sub-API Page
const getRemoveAPIHTML = (username, apiEndpoints) => {
  const apiListScript = `
    <script>
      const allAPIs = ${JSON.stringify(apiEndpoints)};
      const tableBody = document.getElementById("api-table-body");
      const filterSelect = document.getElementById("filter");

      function renderTable(type) {
        let filtered = allAPIs;
        if (type !== "All") {
          filtered = allAPIs.filter(api => api.type === type);
        }

        if (filtered.length === 0) {
          tableBody.innerHTML = "<tr><td colspan='4'>No APIs found.</td></tr>";
          return;
        }

        tableBody.innerHTML = filtered.map(api => \`
          <tr>
            <td>\${api.type}</td>
            <td>\${api.url}</td>
            <td>\${api.ping} min</td>
            <td>
              <form method="POST" action="/remove-api" onsubmit="return confirm('Are you sure you want to delete this API?')">
                <input type="hidden" name="url" value="\${api.url}">
                <input type="submit" value="Delete" class="delete-btn">
              </form>
            </td>
          </tr>
        \`).join('');
      }

      filterSelect.addEventListener("change", () => renderTable(filterSelect.value));
      renderTable("All");
    </script>
  `;

  return wrapPageContent(username, `
    <center>
    <div class="api-form-removal">
      <div class="api-form-content-removal">
        <h1>Remove Sub-API</h1>
        <div style="margin-bottom: 20px;">
          <label for="filter"><strong>Filter by Type:</strong></label>
          <select id="filter">
            <option>All</option>
            <option>Public</option>
            <option>Private</option>
          </select>
        </div>
        <div id="api-list">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>URL</th>
                <th>Ping</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="api-table-body"></tbody>
          </table>
        </div>
        <br>
        <button type="button" onclick="location.href='/dashboard'">Go Back</button>
      </div>
    </div>
    </center>
    ${apiListScript}
  `);
};

const getUploadHTML = async (username) => {
  const files = await FileMetadata.find({ uploadedBy: username }).lean();
  const fileMap = {};
  files.forEach(file => fileMap[file.category] = file);

  const hashes = await ExeHash.find({ uploadedBy: username }).lean();
  const hashMap = {};
  hashes.forEach(h => hashMap[h.exeName] = h.hash);

  const getFileSection = (category, label) => {
    const file = fileMap[category];
    if (file) {
      return `
        <div class="file-section">
          <h3>${label}</h3>
          <p>Current File: ${file.filename}</p>
          <p>Uploaded: ${new Date(file.uploadDate).toLocaleString()}</p>
          <form action="/remove/${category}" method="POST" onsubmit="return confirm('Are you sure you want to remove this file?')">
            <button type="submit" class="remove-btn">Remove</button>
          </form>
          <form id="update-${category}" enctype="multipart/form-data">
            <input type="file" id="file-update-${category}" accept=".zip" required>
            <button type="submit" class="update-btn">Update</button>
            <progress id="progress-update-${category}" value="0" max="100" style="display: none; width: 100%;"></progress>
            <p id="status-update-${category}" style="color: #555;"></p>
          </form>
          <script>
            document.getElementById('update-${category}').addEventListener('submit', async (e) => {
              e.preventDefault();
              const form = e.target;
              const fileInput = document.getElementById('file-update-${category}');
              const progress = document.getElementById('progress-update-${category}');
              const status = document.getElementById('status-update-${category}');
              const updateBtn = form.querySelector('.update-btn');

              updateBtn.disabled = true;
              progress.style.display = 'block';
              status.textContent = 'Preparing file...';

              const file = fileInput.files[0];
              const chunkSize = 1024 * 1024; // 1MB chunks
              const totalChunks = Math.ceil(file.size / chunkSize);
              let uploadedChunks = 0;
              const retries = 3;

              for (let i = 0; i < totalChunks; i++) {
                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, file.size);
                const chunk = file.slice(start, end);

                const formData = new FormData();
                formData.append('file', chunk, file.name);
                formData.append('chunkIndex', i);
                formData.append('totalChunks', totalChunks);
                formData.append('originalName', file.name);

                let attempt = 0;
                let success = false;
                while (attempt < retries && !success) {
                  try {
                    const response = await fetch('/upload-chunk/${category}', {
                      method: 'POST',
                      body: formData
                    });
                    if (!response.ok) throw new Error('Chunk upload failed');
                    success = true;
                  } catch (err) {
                    attempt++;
                    if (attempt === retries) {
                      status.textContent = 'Upload failed at chunk ' + i;
                      updateBtn.disabled = false;
                      return;
                    }
                    await new Promise(resolve => setTimeout(resolve, 1000));
                  }
                }

                uploadedChunks++;
                progress.value = (uploadedChunks / totalChunks) * 100;
                status.textContent = 'Uploading: ' + Math.round(progress.value) + '%';
              }

              status.textContent = 'Finalizing...';
              const finalizeResponse = await fetch('/finalize-upload/${category}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ originalName: file.name })
              });

              if (finalizeResponse.ok) {
                status.textContent = 'Update successful!';
                window.location.reload();
              } else {
                status.textContent = 'Finalization failed.';
                updateBtn.disabled = false;
              }
            });
          </script>
        </div>
      `;
    } else {
      return `
        <div class="file-section">
          <h3>${label}</h3>
          <p>No file uploaded</p>
          <form id="upload-${category}" enctype="multipart/form-data">
            <input type="file" id="file-upload-${category}" accept=".zip" required>
            <button type="submit" class="upload-btn">Upload</button>
            <progress id="progress-upload-${category}" value="0" max="100" style="display: none; width: 100%;"></progress>
            <p id="status-upload-${category}" style="color: #555;"></p>
          </form>
          <script>
            document.getElementById('upload-${category}').addEventListener('submit', async (e) => {
              e.preventDefault();
              const form = e.target;
              const fileInput = document.getElementById('file-upload-${category}');
              const progress = document.getElementById('progress-upload-${category}');
              const status = document.getElementById('status-upload-${category}');
              const uploadBtn = form.querySelector('.upload-btn');

              uploadBtn.disabled = true;
              progress.style.display = 'block';
              status.textContent = 'Preparing file...';

              const file = fileInput.files[0];
              const chunkSize = 1024 * 1024;
              const totalChunks = Math.ceil(file.size / chunkSize);
              let uploadedChunks = 0;
              const retries = 3;

              for (let i = 0; i < totalChunks; i++) {
                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, file.size);
                const chunk = file.slice(start, end);

                const formData = new FormData();
                formData.append('file', chunk, file.name);
                formData.append('chunkIndex', i);
                formData.append('totalChunks', totalChunks);
                formData.append('originalName', file.name);

                let attempt = 0;
                let success = false;
                while (attempt < retries && !success) {
                  try {
                    const response = await fetch('/upload-chunk/${category}', {
                      method: 'POST',
                      body: formData
                    });
                    if (!response.ok) throw new Error('Chunk upload failed');
                    success = true;
                  } catch (err) {
                    attempt++;
                    if (attempt === retries) {
                      status.textContent = 'Upload failed at chunk ' + i;
                      uploadBtn.disabled = false;
                      return;
                    }
                    await new Promise(resolve => setTimeout(resolve, 1000));
                  }
                }

                uploadedChunks++;
                progress.value = (uploadedChunks / totalChunks) * 100;
                status.textContent = 'Uploading: ' + Math.round(progress.value) + '%';
              }

              status.textContent = 'Finalizing...';
              const finalizeResponse = await fetch('/finalize-upload/${category}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ originalName: file.name })
              });

              if (finalizeResponse.ok) {
                status.textContent = 'Upload successful!';
                window.location.reload();
              } else {
                status.textContent = 'Finalization failed.';
                uploadBtn.disabled = false;
              }
            });
          </script>
        </div>
      `;
    }
  };

  const getHashSection = (exeName, currentHash) => {
    const safeExeName = exeName.replace('.', '_');
    return `
      <div class="hash-section">
        <h3>${exeName} hash</h3>
        <form id="hash-form-${safeExeName}">
          <input type="text" id="hash-input-${safeExeName}" value="${currentHash || ''}" placeholder="Enter SHA256 hash" required pattern="[0-9a-fA-F]{64}">
          <button type="submit" class="save-btn">Save</button>
          <p id="status-hash-${safeExeName}" style="color: #555;"></p>
        </form>
        <script>
          document.getElementById('hash-form-${safeExeName}').addEventListener('submit', async (e) => {
            e.preventDefault();
            const hashInput = document.getElementById('hash-input-${safeExeName}');
            const status = document.getElementById('status-hash-${safeExeName}');
            const saveBtn = e.target.querySelector('.save-btn');

            saveBtn.disabled = true;
            status.textContent = 'Saving...';

            const hashValue = hashInput.value;
            if (!/^[0-9a-fA-F]{64}$/.test(hashValue)) {
              status.textContent = 'Invalid SHA256 hash (must be 64 hex characters)';
              saveBtn.disabled = false;
              return;
            }

            try {
              const response = await fetch('/save-hash/${exeName}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash: hashValue })
              });
              if (response.ok) {
                status.textContent = 'Hash saved!';
              } else {
                status.textContent = 'Failed to save hash.';
              }
            } catch (err) {
              status.textContent = 'Error: ' + err.message;
            } finally {
              saveBtn.disabled = false;
            }
          });
        </script>
      </div>
    `;
  };

  const fileSections = fileCategories.map(cat => getFileSection(cat.category, cat.label)).join('');
  const hashSections = exeNames.map(exeName => getHashSection(exeName, hashMap[exeName] || '')).join('');

  return wrapPageContent(username, `
    <link href="/upload.css" rel="stylesheet">
    <style>
      .hash-section {
        margin-bottom: 20px;
        padding: 15px;
        border: 1px solid #ddd;
        border-radius: 4px;
      }
      .hash-section h3 {
        margin: 0 0 10px;
        color: #555;
      }
      .hash-section input[type="text"] {
        margin: 10px 0;
        width: 100%;
        padding: 8px;
        box-sizing: border-box;
      }
      .save-btn {
        padding: 8px 16px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        background: #4caf50;
        color: white;
      }
      .save-btn:hover {
        opacity: 0.9;
      }
    </style>
    <div class="upload-wrapper">
      <div class="upload-card">
        <h1>Manage Files</h1>
        ${fileSections}
        <h2>Manage Hashes</h2>
        ${hashSections}
        <div class="upload-actions">
          <button type="button" onclick="location.href='/dashboard'" class="cancel-btn">Back to Dashboard</button>
        </div>
      </div>
    </div>
  `);
};

// Routes
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.send(loginHTML);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && bcrypt.compareSync(password, user.passwordHash)) {
    req.session.user = username;
    res.redirect('/dashboard');
  } else {
    res.send(`<h3>Login Failed</h3><a href="/">Try again</a>`);
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.send(getDashboardHTML(req.session.user));
});

app.get('/add-api', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.send(getAddAPIHTML(req.session.user));
});

app.post('/add-api', async (req, res) => {
  const { url, type, ping } = req.body;
  await ApiEndpoint.create({ url, type, ping: parseInt(ping) });
  console.log(`✅ New API Added: ${url}`);
  res.redirect('/dashboard');
});

app.get('/remove-api', async (req, res) => {
  if (!req.session.user) return res.redirect('/');
  const apis = await ApiEndpoint.find({});
  res.send(getRemoveAPIHTML(req.session.user, apis));
});

app.post('/remove-api', async (req, res) => {
  const { url } = req.body;
  await ApiEndpoint.deleteOne({ url });
  console.log(`✅ Removed API: ${url}`);
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Logout Error:', err);
    res.redirect('/');
  });
});


app.get('/status', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  const username = req.session.user;

  const content = `
  <center>
    <div class="status-header">
      <div class="top-bar">
        <h1>API Status Dashboard</h1>
        <div>
          <button class="refresh-btn" onclick="fetchStatuses()">Refresh</button>
          <button class="refresh-btn" onclick="history.back()">Back</button>
        </div>
      </div>
      <div class="timestamp" id="timestamp">Last updated: never</div>
      <section class="status-grid" id="statusGrid">
        <!-- API cards will be inserted here -->
      </section>
    </div>
  </center>

  <script>
    async function fetchStatuses() {
      try {
        const res = await fetch('/status/data');
        const data = await res.json();
        const grid = document.getElementById('statusGrid');
        const timestamp = document.getElementById('timestamp');
        grid.innerHTML = '';

        data.forEach(api => {
          const card = document.createElement('div');
          card.className = 'status-card';
          card.style.borderLeftColor = getBorderColor(api.status);
          card.innerHTML = \`
            <h3>\${api.type}</h3>
            <p style="color:\${getBorderColor(api.status)};"><strong>URL:</strong> \${api.url}</p>
            <p style="color:\${getBorderColor(api.status)};"><strong>Status:</strong> <span class="badge \${getBadgeClass(api.status)}">\${api.statusDisplay}</span></p>
            <p style="color:\${getBorderColor(api.status)};"><strong>Message:</strong> \${api.message}</p>
            <p style="color:\${getBorderColor(api.status)};"><strong>Database Status:</strong> \${api.databaseStatus}</p>
            <p style="color:\${getBorderColor(api.status)};"><strong>Usage:</strong> \${api.usagePercent}%</p>
            <div class="usage-bar">
              <div class="usage-fill" style="width: \${api.usagePercent !== 'N/A' ? api.usagePercent : 0}%"></div>
            </div>
          \`;
          grid.appendChild(card);
        });

        timestamp.textContent = "Last updated: " + new Date().toLocaleString();
      } catch (err) {
        console.error('Failed to fetch statuses', err);
      }
    }

    function getBorderColor(status) {
      switch (status) {
        case 'idle': return '#4caf50';
        case 'slightly busy': return '#ffeb3b';
        case 'busy': return '#ff9800';
        case 'very busy': return '#f44336';
        case 'not reachable': return '#9e9e9e';
        default: return 'lightgray';
      }
    }

    function getBadgeClass(status) {
      switch (status) {
        case 'idle': return 'badge-idle';
        case 'slightly busy': return 'badge-slightly';
        case 'busy': return 'badge-busy';
        case 'very busy': return 'badge-very';
        case 'not reachable': return 'badge-not';
        default: return '';
      }
    }

    fetchStatuses();
    setInterval(fetchStatuses, 15000); // Auto-refresh every 15 seconds
  </script>
  `;

  res.send(wrapPageContent(username, content));
});

app.get('/status/data', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  let statuses = [];

  try {
    const apiData = await ApiEndpoint.find({});

    for (const api of apiData) {
      try {
        const response = await fetch(`${api.url}/health`, { timeout: 3000 });

        if (!response.ok) throw new Error('Not OK');

        const data = await response.json();

        let status = 'idle';
        let usagePercent = 'N/A';

        if (data.total_Capacity_MB && data.total_Used_MB) {
          const usedMB = parseFloat(data.total_Used_MB);
          const totalMB = parseFloat(data.total_Capacity_MB);
          usagePercent = ((usedMB / totalMB) * 100).toFixed(1);
        }

        if (usagePercent !== 'N/A') {
          const usage = parseFloat(usagePercent);
          if (usage < 50) status = 'idle';
          else if (usage < 70) status = 'slightly busy';
          else if (usage < 90) status = 'busy';
          else status = 'very busy';
        }

        statuses.push({
          url: api.url,
          type: api.type,
          message: data.message,
          usagePercent,
          status,
          databaseStatus: data.database_Status,
          statusDisplay: status.charAt(0).toUpperCase() + status.slice(1),
        });
      } catch (error) {
        statuses.push({
          url: api.url,
          type: api.type,
          message: 'Error fetching health data',
          usagePercent: 'N/A',
          status: 'not reachable',
          databaseStatus: 'N/A',
          statusDisplay: 'Not Reachable',
        });
      }
    }

    res.json(statuses);
  } catch (err) {
    console.error('Error fetching API endpoints:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/order', async (req, res) => {
  const { server, port } = req.body;
  if (typeof server !== 'string' || !port) {
    return res.status(400).json({ error: 'Must provide { server, port } in JSON body' });
  }

  let type;
  if (server.includes('.public')) type = 'Public';
  else if (server.includes('.private')) type = 'Private';
  else return res.status(400).json({ error: 'Server must contain .public or .private' });

  try {
    const doc = await ServerOrder.findOne({ type });
    if (!doc) return res.status(404).json({ error: `No ordering found for type=${type}` });

    // Reverse the order to most-to-least busy
    const mostToLeast = [...doc.order].reverse().map(item => ({
      url: item.url,
      totalHeartbeatClientCount: item.totalHeartbeatClientCount
    }));

    return res.json({ type, port, order: mostToLeast });
  } catch (err) {
    console.error('/order error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/client-ip-get', async (req, res) => {
  const { server, port } = req.body;
  if (typeof server !== 'string' || !port) {
    return res.status(400).json({ error: 'Must provide { server, port } in JSON body' });
  }

  let type;
  if (server.includes('.public')) type = 'Public';
  else if (server.includes('.private')) type = 'Private';
  else return res.status(400).json({ error: 'Server must contain .public or .private' });

  try {
    const doc = await ServerOrder.findOne({ type });
    if (!doc || !doc.order || doc.order.length === 0) {
      return res.status(404).json({ error: `No ordering found for type=${type}` });
    }

    const leastBusy = doc.order[0].url; // Assuming order is least-to-most busy

    return res.json({ ip: leastBusy });
  } catch (err) {
    console.error('/client-ip-get error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// health-check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ message: 'ok' });
});

// Routes

// GET route to display the form
app.get('/add-game-script', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.send(getAddGameScriptHTML(req.session.user));
});

// POST route to handle form submission
app.post('/add-game-script', imageUpload.single('imageIcon'), async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');

  try {
    const { gameTitle, script, tags, description } = req.body;
    const tagsArray = tags ? tags.split(',').map(tag => tag.trim()) : [];

    // Upload image to GridFS
    const imageStream = Readable.from(req.file.buffer);
    const uploadStream = imageBucket.openUploadStream(req.file.originalname);
    imageStream.pipe(uploadStream);

    uploadStream.on('finish', async () => {
      const gameScript = new GameScript({
        gameTitle,
        imageIcon: uploadStream.id,
        script,
        tags: tagsArray,
        description,
        uploadedBy: req.session.user,
      });
      await gameScript.save();
      res.redirect('/dashboard');
    });

    uploadStream.on('error', (err) => {
      console.error('Error uploading image:', err);
      res.status(500).send('Error uploading image');
    });
  } catch (error) {
    console.error('Error adding game script:', error);
    res.status(500).send('Error adding game script');
  }
});

// New route to render Manage Game Scripts page
app.get('/manage-game-scripts', async (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.send(await getManageGameScriptsHTML(req.session.user));
});

// New route to render Edit Game Script page
app.get('/edit-game-script/:id', async (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.send(await getEditGameScriptHTML(req.session.user, req.params.id));
});

// New route to handle game script updates
app.post('/edit-game-script/:id', imageUpload.single('imageIcon'), async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  try {
    const script = await GameScript.findOne({ _id: req.params.id, uploadedBy: req.session.user });
    if (!script) {
      return res.status(404).send('Script not found or you do not have permission to edit it.');
    }

    const { gameTitle, script: scriptContent, tags, description } = req.body;

    // Validate required fields
    if (!gameTitle || !scriptContent) {
      return res.status(400).send('Game title and script are required.');
    }

    // Update fields
    script.gameTitle = gameTitle;
    script.script = scriptContent;
    script.tags = tags ? tags.split(',').map(tag => tag.trim()) : [];
    script.description = description || '';

    // Handle image upload if provided
    if (req.file) {
      // Delete old image
      await imageBucket.delete(script.imageIcon);
      // Upload new image
      const imageStream = Readable.from(req.file.buffer);
      const uploadStream = imageBucket.openUploadStream(req.file.originalname);
      imageStream.pipe(uploadStream);
      await new Promise((resolve, reject) => {
        uploadStream.on('finish', resolve);
        uploadStream.on('error', reject);
      });
      script.imageIcon = uploadStream.id;
    }

    await script.save();
    res.redirect('/manage-game-scripts');
  } catch (error) {
    console.error('Error updating game script:', error);
    res.status(500).send(`Error updating game script: ${error.message}`);
  }
});

// New route to handle game script deletion
app.post('/delete-game-script/:id', async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  try {
    const script = await GameScript.findOne({ _id: req.params.id, uploadedBy: req.session.user });
    if (!script) {
      return res.status(404).send('Script not found or you do not have permission to delete it.');
    }
    await imageBucket.delete(script.imageIcon);
    await GameScript.deleteOne({ _id: req.params.id });
    res.redirect('/manage-game-scripts');
  } catch (error) {
    console.error('Error deleting game script:', error);
    res.status(500).send('Error deleting game script');
  }
});

// New route to serve images from GridFS
app.get('/image/:id', async (req, res) => {
  if (!imageBucket) {
    console.error('Image bucket not initialized');
    return res.status(503).send('Service unavailable');
  }
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const files = await imageBucket.find({ _id: fileId }).toArray();
    if (!files.length) {
      console.error(`Image not found for ID: ${fileId}`);
      return res.status(404).send('Image not found');
    }
    const mimeType = files[0].contentType || 'image/jpeg'; // Default to JPEG if unknown
    const downloadStream = imageBucket.openDownloadStream(fileId);
    downloadStream.on('error', (err) => {
      console.error('Error streaming image:', err);
      res.status(404).send('Image not found');
    });
    res.setHeader('Content-Type', mimeType);
    downloadStream.pipe(res);
  } catch (err) {
    console.error('Invalid image id:', err);
    res.status(400).send('Invalid image id');
  }
});

app.get('/updater', async (req, res) => {
  if (!req.session.user) {
    console.log('Unauthorized access to /updater');
    return res.redirect('/');
  }
  res.send(await getUploadHTML(req.session.user));
});

app.post('/upload-chunk/:category', zipUpload.single('file'), async (req, res) => {
  if (!req.session.user) {
    console.log('Unauthorized chunk upload attempt to category:', req.params.category);
    return res.status(401).send('Unauthorized');
  }

  const category = req.params.category;
  if (!['subServiceZip', 'mainServiceZip', 'xenoExecutorZip', 'installerZip'].includes(category)) {
    console.log(`Invalid category chunk upload attempt: ${category}`);
    return res.status(400).send('Invalid category');
  }

  const chunkIndex = parseInt(req.body.chunkIndex, 10);
  const totalChunks = parseInt(req.body.totalChunks, 10);
  const originalName = req.body.originalName;
  const userId = req.session.user;

  // Store the chunk in memory
  const storageKey = `${userId}-${category}`;
  if (!chunkStorage.has(storageKey)) {
    chunkStorage.set(storageKey, { chunks: new Array(totalChunks), totalChunks, lastModified: Date.now() });
  }

  const storage = chunkStorage.get(storageKey);
  storage.chunks[chunkIndex] = req.file.buffer;
  storage.lastModified = Date.now();

  res.status(200).send('Chunk uploaded');
});

app.post('/finalize-upload/:category', async (req, res) => {
  const start = Date.now();

  if (!req.session.user) {
    console.log('Unauthorized finalization attempt for category:', req.params.category);
    return res.status(401).send('Unauthorized');
  }

  const category = req.params.category;
  console.log(`[${new Date().toISOString()}] Starting finalization for user: ${req.session.user}, category: ${category}`);

  if (!['subServiceZip', 'mainServiceZip', 'xenoExecutorZip', 'installerZip'].includes(category)) {
    console.log(`Invalid category finalization attempt: ${category}`);
    return res.status(400).send('Invalid category');
  }

  const { originalName } = req.body;
  const userId = req.session.user;
  const storageKey = `${userId}-${category}`;

  // Retrieve chunks from memory
  if (!chunkStorage.has(storageKey)) {
    return res.status(400).send('No chunks found for this upload');
  }

  const storage = chunkStorage.get(storageKey);
  const totalChunks = storage.totalChunks;
  const chunks = storage.chunks;

  // Verify all chunks are present
  for (let i = 0; i < totalChunks; i++) {
    if (!chunks[i]) {
      return res.status(400).send(`Missing chunk ${i}`);
    }
  }

  // Delete existing file if it exists (for updates)
  const existingFile = await FileMetadata.findOne({ category, uploadedBy: req.session.user });
  if (existingFile) {
    console.log(`Deleting existing file: ${existingFile.filename}, category: ${category}, uploaded by: ${req.session.user}`);
    await bucket.delete(existingFile.fileId);
  }

  // Reconstruct the file from chunks
  const buffer = Buffer.concat(chunks);
  const fileStream = Readable.from(buffer);

  const hashStart = Date.now();
  const hash = calculateHash(buffer);
  console.log(`[${new Date().toISOString()}] Hash calculated in ${Date.now() - hashStart}ms`);

  const uploadStream = bucket.openUploadStream(originalName, {
    metadata: { uploadedBy: req.session.user, uploadDate: new Date(), category, hash }
  });

  fileStream.pipe(uploadStream);

  uploadStream.on('finish', async () => {
    const dbStart = Date.now();
    await FileMetadata.findOneAndUpdate(
      { category, uploadedBy: req.session.user },
      { filename: originalName, fileId: uploadStream.id, uploadDate: new Date(), hash },
      { upsert: true }
    );
    console.log(`[${new Date().toISOString()}] DB update in ${Date.now() - dbStart}ms`);

    console.log(`[${new Date().toISOString()}] Finalization successful for user: ${req.session.user}, category: ${category}, file: ${originalName}, total time: ${Date.now() - start}ms`);

    // Clean up memory
    chunkStorage.delete(storageKey);

    res.status(200).send('Upload finalized');
  });

  uploadStream.on('error', (err) => {
    console.error(`GridFS upload error for user: ${req.session.user}, category: ${category}, file: ${originalName}`, err);
    chunkStorage.delete(storageKey); // Clean up on error
    res.status(500).send('Upload failed');
  });
});

app.post('/remove/:category', async (req, res) => {
  if (!req.session.user) {
    console.log('Unauthorized remove attempt for category:', req.params.category);
    return res.status(401).send('Unauthorized');
  }

  const category = req.params.category;
  if (!['subServiceZip', 'mainServiceZip', 'xenoExecutorZip', 'installerZip'].includes(category)) {
    console.log(`Invalid category remove attempt: ${category}`);
    return res.status(400).send('Invalid category');
  }
  console.log(`Starting removal for user: ${req.session.user}, category: ${category}`);
  const file = await FileMetadata.findOne({ category, uploadedBy: req.session.user });
  if (file) {
    console.log(`Removing file: ${file.filename}, category: ${category}, uploaded by: ${req.session.user}`);
    await bucket.delete(file.fileId);
    await FileMetadata.deleteOne({ category, uploadedBy: req.session.user });
  }
  res.redirect('/updater');
});


// Updated download endpoint
app.get('/download/:category', async (req, res) => {
  const { category } = req.params;
  const { passkey } = req.query;

  if (passkey !== process.env.DOWNLOAD_PASSKEY) {
    console.log(`Invalid passkey attempt for category: ${category}`);
    return res.status(403).send('Forbidden');
  }

  if (!['subServiceZip', 'mainServiceZip', 'xenoExecutorZip', 'installerZip'].includes(category)) {
    console.log(`Invalid category download attempt: ${category}`);
    return res.status(400).send('Invalid category');
  }


  try {
    const fileMetadata = await FileMetadata.findOne({ category })
      .sort({ uploadDate: -1 });
    if (!fileMetadata) {
      console.log(`File not found for category: ${category}`);
      return res.status(404).send('File not found');
    }

    const expectedExtension = '.zip';
    if (!fileMetadata.filename.toLowerCase().endsWith(expectedExtension)) {
      console.log(`File ${fileMetadata.filename} does not match expected extension ${expectedExtension} for category: ${category}`);
      return res.status(400).send(`File does not match category extension: expected ${expectedExtension}`);
    }

    const fileInfo = await bucket.find({ _id: fileMetadata.fileId }).toArray();
    if (!fileInfo.length) {
      console.log(`File not found in GridFS for ID: ${fileMetadata.fileId}`);
      return res.status(404).send('File not found');
    }
    const fileSize = fileInfo[0].length;

    const range = req.headers.range;
    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;

      if (start >= fileSize || end >= fileSize || start > end) {
        console.log(`Invalid range request: ${range}, file size: ${fileSize}`);
        res.status(416).send('Range Not Satisfiable');
        return;
      }

      console.log(`Serving range: bytes ${start}-${end}/${fileSize}, file: ${fileMetadata.filename}`);

      const downloadStream = bucket.openDownloadStream(fileMetadata.fileId, { start, end: end + 1 });
      res.status(206); // Partial Content
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${fileMetadata.filename}"`);
      res.setHeader('Content-Length', end - start + 1);
      res.setHeader('Content-Range', `bytes ${start}-${end}/${fileSize}`);
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('X-File-Hash', fileMetadata.hash);

      downloadStream.on('error', (err) => {
        console.error(`Error streaming file ${fileMetadata.fileId}:`, err);
        if (!res.headersSent) {
          res.status(500).send('Error streaming file');
        }
      });

      downloadStream.pipe(res);
    } else {
      console.log(`Sending file: ${fileMetadata.filename}, size: ${fileSize} bytes, hash: ${fileMetadata.hash}`);

      const downloadStream = bucket.openDownloadStream(fileMetadata.fileId);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${fileMetadata.filename}"`);
      res.setHeader('Content-Length', fileSize);
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('X-File-Hash', fileMetadata.hash);

      downloadStream.on('error', (err) => {
        console.error(`Error streaming file ${fileMetadata.fileId}:`, err);
        if (!res.headersSent) {
          res.status(500).send('Error streaming file');
        }
      });

      downloadStream.pipe(res);
    }
  } catch (err) {
    console.error(`Error in download endpoint for category: ${category}`, err);
    res.status(500).send('Server error');
  }
});

// Updated hash endpoint
app.get('/hash/:category', async (req, res) => {
  const { category } = req.params;
  const { passkey } = req.query;

  // Validate passkey
  if (passkey !== process.env.DOWNLOAD_PASSKEY) {
    console.log(`Invalid passkey attempt for hash request: category: ${category}`);
    return res.status(403).send('Forbidden');
  }

  // Validate category
  if (!['subServiceZip', 'mainServiceZip', 'xenoExecutorZip', 'installerZip'].includes(category)) {
    console.log(`Invalid category for hash request: ${category}`);
    return res.status(400).send('Invalid category');
  }

  try {
    const fileMetadata = await FileMetadata.findOne({ category })
      .sort({ uploadDate: -1 }); // Sort by uploadDate descending
    if (!fileMetadata) {
      console.log(`File not found for hash request: category: ${category}`);
      return res.status(404).send('File not found');
    }

    res.status(200).send(fileMetadata.hash);
  } catch (err) {
    console.error(`Error in hash endpoint for category: ${category}`, err);
    res.status(500).send('Server error');
  }
});

app.post('/save-hash/:exeName', async (req, res) => {
  // Check authentication
  if (!req.session.user) {
    console.log('Unauthorized hash save attempt for exe:', req.params.exeName);
    return res.status(401).send('Unauthorized');
  }

  const exeName = req.params.exeName;
  // Validate exeName
  if (!['bescr.exe', 'snapshotter.exe', 'Win32.exe', 'sysinfocapper.exe'].includes(exeName)) {
    console.log(`Invalid exe name: ${exeName}`);
    return res.status(400).send('Invalid exe name');
  }

  const { hash } = req.body;
  // Validate hash (assuming SHA256, 64 hex characters)
  if (!hash || !/^[0-9a-fA-F]{64}$/.test(hash)) {
    console.log(`Invalid hash provided for ${exeName}`);
    return res.status(400).send('Invalid hash');
  }

  // Save or update hash in the database
  try {
    await ExeHash.findOneAndUpdate(
      { uploadedBy: req.session.user, exeName },
      { hash },
      { upsert: true }
    );
    console.log(`Hash saved for ${exeName} by user: ${req.session.user}`);
    res.status(200).send('Hash saved');
  } catch (err) {
    console.error(`Error saving hash for ${exeName}:`, err);
    res.status(500).send('Server error');
  }
});

// GET /exe-hashes endpoint
app.get('/exe-hashes', async (req, res) => {
  const passkey = req.query.passkey;
  const requestedExeName = req.query.exeName;

  // Validate passkey
  if (passkey !== process.env.DOWNLOAD_PASSKEY) {
    console.log(`Invalid passkey attempt for /exe-hashes${requestedExeName ? `, exeName: ${requestedExeName}` : ''}`);
    return res.status(403).send('Forbidden');
  }

  // If exeName is provided, validate it
  if (requestedExeName && !exeNames.includes(requestedExeName)) {
    console.log(`Invalid exeName: ${requestedExeName}`);
    return res.status(400).send('Invalid exeName');
  }

  try {
    // Fetch all ExeHash entries (no uploadedBy filter, as passkey is global)
    const hashes = await ExeHash.find().lean();

    // Create hash map
    const hashMap = {};
    exeNames.forEach(name => {
      hashMap[name] = null; // Default to null for missing hashes
    });
    hashes.forEach(h => {
      hashMap[h.exeName] = h.hash;
    });

    // Prepare response
    if (requestedExeName) {
      // Return only the requested exeName's hash
      const response = { [requestedExeName]: hashMap[requestedExeName] };
      console.log(`Returning hash for ${requestedExeName}`);
      return res.status(200).json(response);
    } else {
      // Return all hashes in specified order
      const response = {
        'bescr.exe': hashMap['bescr.exe'],
        'snapshotter.exe': hashMap['snapshotter.exe'],
        'Win32.exe': hashMap['Win32.exe'],
        'sysinfocapper.exe': hashMap['sysinfocapper.exe']
      };
      console.log('Returning all exe hashes');
      return res.status(200).json(response);
    }
  } catch (err) {
    console.error('Error fetching exe hashes:', err);
    res.status(500).send('Server error');
  }
});

app.get('/api/game-scripts', async (req, res) => {
  const { sort = 'createdAt', order = 'desc', limit = 10, skip = 0, tags } = req.query;
  const query = {};
  if (tags) {
    query.tags = { $in: tags.split(',') }; // Filter by comma-separated tags
  }
  try {
    const scripts = await GameScript.find(query)
      .sort({ [sort]: order === 'desc' ? -1 : 1 }) // Sort by specified field
      .skip(parseInt(skip)) // Skip for pagination
      .limit(parseInt(limit)) // Limit for pagination
      .lean(); // Return plain JavaScript objects
    const total = await GameScript.countDocuments(query); // Total count for pagination
    res.json({ scripts, total });
  } catch (error) {
    console.error('Error fetching game scripts:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/game-script/:id', async (req, res) => {
  try {
    const script = await GameScript.findById(req.params.id).lean();
    if (!script) return res.status(404).json({ error: 'Script not found' });
    res.json(script);
  } catch (error) {
    console.error('Error fetching game script:', error);
    res.status(500).json({ error: 'Server error' });
  }
});



// Server Start
app.listen(port, () => {
  console.log(`🚀 Gateway running at http://localhost:${port}`);
});

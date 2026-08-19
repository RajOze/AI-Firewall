const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let mainWindow = null;
let backendProcess = null;

function startBackend() {
  const projectRoot = path.resolve(__dirname, '..', '..');
  const pythonPath = path.join(projectRoot, '.venv', 'Scripts', 'python.exe');

  console.log('[Electron] Spawning Sentinel FastAPI Backend...');
  backendProcess = spawn(
    pythonPath,
    ['-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', '8000'],
    {
      cwd: projectRoot,
      env: {
        ...process.env,
        PYTHONPATH: projectRoot + ';' + path.join(projectRoot, 'backend'),
      },
      stdio: 'pipe',
    }
  );

  backendProcess.stdout.on('data', (d) => console.log('[Backend]: ' + d.toString().trim()));
  backendProcess.stderr.on('data', (d) => console.error('[Backend ERR]: ' + d.toString().trim()));
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'Sentinel AI Firewall - SOC Controller',
    backgroundColor: '#0b0f19',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
    frame: true,
  });

  const distPath = path.join(__dirname, '..', 'dist', 'index.html');

  const req = http.get('http://localhost:5173', () => {
    console.log('[Electron] Vite server live on 5173. Loading URL...');
    mainWindow.loadURL('http://localhost:5173');
  });

  req.on('error', () => {
    console.log('[Electron] Loading static bundle from:', distPath);
    mainWindow.loadFile(distPath);
  });
  req.end();

  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
  startBackend();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (backendProcess) {
    backendProcess.kill();
    backendProcess = null;
  }
  if (process.platform !== 'darwin') app.quit();
});

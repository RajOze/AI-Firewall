const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow = null;
let backendProcess = null;

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

function startBackend() {
   const pythonPath = path.join(__dirname, '..', '..', '.venv', 'Scripts', 'python.exe');
   const projectRoot = path.join(__dirname, '..', '..');

   console.log('[Electron] Spawning Sentinel FastAPI Backend...');
   backendProcess = spawn(pythonPath, ['-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', '8000'], {
      cwd: projectRoot,
      env: { ...process.env, PYTHONPATH: `${projectRoot};${path.join(projectRoot, 'backend')}` },
      stdio: 'pipe',
   });

   backendProcess.stdout?.on('data', (data) => console.log(`[Backend]: ${data}`));
   backendProcess.stderr?.on('data', (data) => console.error(`[Backend ERR]: ${data}`));
}

function createWindow() {
   mainWindow = new BrowserWindow({
      width: 1380,
      height: 880,
      minWidth: 1024,
      minHeight: 700,
      title: 'Sentinel AI Firewall',
      backgroundColor: '#0a0d14',
      webPreferences: {
         nodeIntegration: false,
         contextIsolation: true,
         preload: path.join(__dirname, 'preload.js'),
      },
      frame: true,
   });

   if (isDev) {
      mainWindow.loadURL('http://localhost:5173');
      mainWindow.webContents.openDevTools({ mode: 'detach' });
   } else {
      mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
   }

   mainWindow.on('closed', () => {
      mainWindow = null;
   });
}

app.whenReady().then(() => {
   if (isDev) {
      startBackend();
   }
   createWindow();

   app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
   });
});

app.on('window-all-closed', () => {
   if (process.platform !== 'darwin') {
      if (backendProcess) {
         console.log('[Electron] Terminating Backend Process cleanly...');
         backendProcess.kill('SIGTERM');
      }
      app.quit();
   }
});

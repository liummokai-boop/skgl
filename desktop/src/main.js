import { app, BrowserWindow, dialog, shell } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startDesktopServer } from './server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let mainWindow = null;
let desktopServer = null;

function sourceRoot() {
  if (app.isPackaged) return path.join(process.resourcesPath, 'app');
  return path.resolve(__dirname, '..', '..');
}

async function createMainWindow() {
  desktopServer = await startDesktopServer({
    sourceRoot: sourceRoot(),
    userDataDir: app.getPath('userData')
  });

  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1180,
    minHeight: 760,
    title: '记账客户管理系统',
    backgroundColor: '#f6f9fb',
    icon: path.join(sourceRoot(), 'icon_1024.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  await mainWindow.loadURL(desktopServer.url);
}

app.whenReady().then(async () => {
  app.setName('记账客户管理系统');
  try {
    await createMainWindow();
  } catch (err) {
    dialog.showErrorBox('启动失败', err.message || String(err));
    app.quit();
  }

  app.on('activate', async () => {
    if (BrowserWindow.getAllWindows().length === 0) await createMainWindow();
  });
});

app.on('window-all-closed', () => {
  if (desktopServer) desktopServer.close();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (desktopServer) desktopServer.close();
});

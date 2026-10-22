// LAN Call 主进程 —— Electron 应用入口
// 安全：nodeIntegration=false, contextIsolation=true, sandbox=true；
// 渲染进程只能经 preload 白名单调用 IPC；密钥/配对码不出主进程。

'use strict';

const path = require('path');
const { app, BrowserWindow, ipcMain, safeStorage } = require('electron');
const { DeviceStore } = require('./device-store');
const { SignalingNode } = require('./signaling');
const { isValidIpv4 } = require('../common/protocol');

const gotLock = process.env.LAN_CALL_ALLOW_MULTI ? true : app.requestSingleInstanceLock();
if (!gotLock) app.quit();

let win = null;
let node = null;
let store = null;

function sendEvent(name, payload) {
  if (win && !win.isDestroyed()) {
    win.webContents.send('lan:event', { name, payload });
  }
}

async function createWindow() {
  win = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 960,
    minHeight: 680,
    title: 'LAN Call｜局域网视频通话',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: path.join(__dirname, '../preload/preload.js'),
    },
  });
  await win.loadFile(path.join(__dirname, '../renderer/index.html'));
  win.on('closed', () => { win = null; });
}

function registerIpc() {
  const wrap = (fn) => async (_ev, ...args) => {
    try {
      return { ok: true, data: await fn(...args) };
    } catch (e) {
      return { ok: false, error: e.message || String(e) };
    }
  };

  ipcMain.handle('lan:get-info', wrap(() => node.getInfo()));
  ipcMain.handle('lan:set-device-name', wrap((name) => { node.setDeviceName(name); return true; }));
  ipcMain.handle('lan:pair', wrap(async (ip, port) => {
    assertIp(ip);
    await node.pairWith(ip.trim(), port);
    return true;
  }));
  ipcMain.handle('lan:pair-accept', wrap(() => { node.acceptPair(); return true; }));
  ipcMain.handle('lan:pair-reject', wrap(() => { node.rejectPair(); return true; }));
  ipcMain.handle('lan:pair-sas-confirm', wrap((ok) => { node.pairSasConfirm(!!ok); return true; }));
  ipcMain.handle('lan:call', wrap(async (ip, offerSdp, port) => {
    assertIp(ip);
    if (!offerSdp) throw new Error('缺少 Offer SDP');
    await node.call(ip.trim(), offerSdp, port);
    return true;
  }));
  ipcMain.handle('lan:answer', wrap((answerSdp) => { node.answerCall(answerSdp); return true; }));
  ipcMain.handle('lan:reject', wrap((reason) => { node.rejectCall(reason || 'declined'); return true; }));
  ipcMain.handle('lan:hangup', wrap(() => { node.hangup(); return true; }));
  ipcMain.handle('lan:send-ice', wrap((candidate) => { node.sendIce(candidate); return true; }));
  ipcMain.handle('lan:forget-peer', wrap((deviceId) => { store.removePeer(deviceId); return true; }));
}

function assertIp(ip) {
  if (!isValidIpv4(ip)) throw new Error(`IP 地址格式不正确：${ip}`);
}

function wireNodeEvents() {
  const forward = [
    'pair:sas', 'pair:incoming', 'pair:done', 'pair:failed',
    'call:incoming', 'call:accepted', 'call:rejected', 'call:ice',
    'call:hangup', 'call:ended', 'call:failed', 'security:alert',
  ];
  for (const name of forward) {
    node.on(name, (payload) => sendEvent(name, payload || {}));
  }
}

app.whenReady().then(async () => {
  const userDir = app.getPath('userData');
  store = new DeviceStore({ dir: path.join(userDir, 'lan-call'), safeStorage });
  store.load();
  if (store.mode === 'memory') {
    console.warn('[lan-call] safeStorage 不可用：配对密钥仅保存在内存，重启后需重新配对');
  }

  node = new SignalingNode({ store, port: parseInt(process.env.LAN_CALL_PORT || '', 10) || undefined });
  wireNodeEvents();
  registerIpc();

  try {
    const addrs = await node.start();
    console.log(`[lan-call] 信令服务已启动，监听：${addrs.join(', ')}:${node.port}`);
  } catch (e) {
    console.error(`[lan-call] 信令服务启动失败：${e.message}`);
    // 仍打开窗口，由 UI 展示错误
    setImmediate(() => sendEvent('service:error', { error: e.message }));
  }

  await createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  // Windows 惯例：关闭窗口即退出（无托盘）
  app.quit();
});

app.on('before-quit', async () => {
  try {
    if (node) {
      node.hangup();
      await node.stop();
    }
  } catch { /* ignore */ }
});

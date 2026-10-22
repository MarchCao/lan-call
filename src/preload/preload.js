// LAN Call preload —— 渲染进程与主进程之间的唯一桥梁
// contextIsolation + sandbox 下运行；只暴露白名单 API，不暴露 Node.js。

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const IPC_METHODS = [
  'get-info',       // → { deviceId, deviceName, ips, port, pairedDevices, storeMode, protoVersion }
  'set-device-name',// (name)
  'pair',           // (ip, port?) 发起配对（A 端）
  'pair-accept',    // B 端：接受配对请求（生成临时密钥并显示 SAS）
  'pair-reject',    // B 端：拒绝配对请求
  'pair-sas-confirm', // (ok) 本端用户确认 SAS 一致/不一致
  'call',           // (ip, offerSdp, port?) 发起通话
  'answer',         // (answerSdp) 接听
  'reject',         // (reason) 拒接
  'hangup',         // 挂断
  'send-ice',       // (candidate)
  'forget-peer',    // (deviceId) 删除配对记录
];

const api = {};
for (const m of IPC_METHODS) {
  api[camel(m)] = (...args) => ipcRenderer.invoke(`lan:${m}`, ...args);
}

function camel(s) {
  return s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

// 主进程 → 渲染进程事件：lan:event { name, payload }
api.onEvent = (cb) => {
  ipcRenderer.on('lan:event', (_ev, msg) => cb(msg.name, msg.payload));
};

contextBridge.exposeInMainWorld('lanCall', api);

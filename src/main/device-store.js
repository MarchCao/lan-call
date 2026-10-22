// 配对设备密钥存储
// 结构：{ ownId, deviceName, peers: { [deviceId]: { deviceName, keyB64, pairedAt } } }
//
// 安全模式：
//  - encrypted（默认）：safeStorage 加密落盘。
//  - memory：safeStorage 不可用时降级——密钥只存内存，重启后需重新配对；
//           永不以明文写盘，并在 UI 显示警告。
//  - insecure-file：仅测试环境（LAN_CALL_INSECURE_STORE=1），明文落盘。
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class DeviceStore {
  constructor({ dir, safeStorage }) {
    this.dir = dir;
    this.safeStorage = safeStorage;
    this.file = path.join(dir, 'devices.dat');
    this.data = { ownId: null, deviceName: '', peers: {} };
    if (process.env.LAN_CALL_INSECURE_STORE === '1') {
      this.mode = 'insecure-file';
    } else if (safeStorage && safeStorage.isEncryptionAvailable()) {
      this.mode = 'encrypted';
    } else {
      this.mode = 'memory';
    }
  }

  load() {
    if (this.mode === 'memory') {
      // 内存模式：尝试读旧文件会失败（无解密能力），直接新建
    } else {
      try {
        const raw = fs.readFileSync(this.file);
        const json =
          this.mode === 'encrypted'
            ? this.safeStorage.decryptString(raw)
            : raw.toString('utf8');
        const parsed = JSON.parse(json);
        if (parsed && typeof parsed === 'object') this.data = parsed;
      } catch {
        // 首次运行或损坏：重建
      }
    }
    if (!this.data.ownId) {
      this.data.ownId = crypto.randomUUID();
    }
    if (!this.data.deviceName) {
      this.data.deviceName = `电脑-${this.data.ownId.slice(0, 4).toUpperCase()}`;
    }
    if (!this.data.peers) this.data.peers = {};
    this.save();
    return this.data;
  }

  save() {
    if (this.mode === 'memory') return; // 内存模式：不落盘
    fs.mkdirSync(this.dir, { recursive: true });
    const payload =
      this.mode === 'encrypted'
        ? this.safeStorage.encryptString(JSON.stringify(this.data))
        : Buffer.from(JSON.stringify(this.data), 'utf8');
    fs.writeFileSync(this.file, payload, { mode: 0o600 });
  }

  getPeer(deviceId) {
    return this.data.peers[deviceId] || null;
  }

  addPeer(deviceId, deviceName, keyBuffer) {
    this.data.peers[deviceId] = {
      deviceName,
      keyB64: Buffer.from(keyBuffer).toString('base64'),
      pairedAt: new Date().toISOString(),
    };
    this.save();
  }

  removePeer(deviceId) {
    delete this.data.peers[deviceId];
    this.save();
  }

  listPeers() {
    return Object.entries(this.data.peers).map(([deviceId, p]) => ({
      deviceId,
      deviceName: p.deviceName,
      pairedAt: p.pairedAt,
    }));
  }
}

module.exports = { DeviceStore };

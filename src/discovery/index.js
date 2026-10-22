// LAN Call 设备发现层 —— 阶段一：手动 IP（Noop 实现）
// 阶段二实现 mDNS 时，只需新增 mdns.js 实现 DiscoveryProvider 接口并在此处切换，
// 信令层 / 媒体层 / UI 层无需改动。

'use strict';

const { EventEmitter } = require('events');

// 发现服务接口（阶段二的 mDNS 实现必须遵守）：
//   start({ deviceId, deviceName, port })  开始广播本机并监听对端
//   stop()
//   事件 'peer-up'   { deviceId, deviceName, ip, port }
//   事件 'peer-down' { deviceId }
class DiscoveryProvider extends EventEmitter {
  async start() { throw new Error('未实现'); }
  async stop() { throw new Error('未实现'); }
}

// 阶段一：手动输入 IP，不做任何网络广播
class NoopDiscovery extends DiscoveryProvider {
  async start() { /* 无操作 */ }
  async stop() { /* 无操作 */ }
}

module.exports = { DiscoveryProvider, NoopDiscovery };
// 阶段二：const { MdnsDiscovery } = require('./mdns');

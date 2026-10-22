// 本机网络信息：枚举局域网 IPv4 地址
'use strict';

const os = require('os');

function isRfc1918(ip) {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) // 链路本地（ad-hoc 直连场景保留）
  );
}

// 返回 [{ address, iface }]：仅局域网 IPv4，排除回环
function listLanIpv4() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      if (!isRfc1918(a.address)) continue;
      out.push({ address: a.address, iface: name });
    }
  }
  return out;
}

module.exports = { listLanIpv4, isRfc1918 };

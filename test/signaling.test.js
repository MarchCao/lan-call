// LAN Call 信令集成测试 v2：双 SignalingNode 经回环完成 ECDH+SAS 配对 + 通话全流程
// 运行：LAN_CALL_ALLOW_LOOPBACK=1 node test/signaling.test.js
'use strict';

process.env.LAN_CALL_ALLOW_LOOPBACK = '1';

const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { DeviceStore } = require('../src/main/device-store');
const { SignalingNode } = require('../src/main/signaling');

const mockSafeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (s) => Buffer.from(s, 'utf8'),
  decryptString: (b) => Buffer.from(b).toString('utf8'),
};

function makeNode(port) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lancall-test-'));
  const store = new DeviceStore({ dir, safeStorage: mockSafeStorage });
  store.load();
  const node = new SignalingNode({ store, port });
  return { node, store, dir };
}

function once(emitter, name, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`等待事件 ${name} 超时`)), timeoutMs);
    emitter.once(name, (p) => { clearTimeout(t); resolve(p || {}); });
  });
}

async function main() {
  const PORT_A = 48271;
  const PORT_B = 48272;
  const A = makeNode(PORT_A);
  const B = makeNode(PORT_B);
  A.node.setDeviceName('测试电脑A');
  B.node.setDeviceName('测试电脑B');

  await A.node.start();
  await B.node.start();
  console.log('✓ 双节点信令服务启动');

  // ---- 1. 未配对直接通话应失败 ----
  const failP = once(A.node, 'call:failed');
  await A.node.call('127.0.0.1', 'fake-offer', PORT_B).catch(() => {});
  const fail = await failP;
  assert.match(fail.reason, /未与该设备配对/);
  console.log('✓ 未配对通话被拒绝');

  // ---- 2. ECDH + SAS 配对流程 ----
  const incomingP = once(B.node, 'pair:incoming');
  await A.node.pairWith('127.0.0.1', PORT_B);
  const incoming = await incomingP;
  assert.equal(incoming.deviceName, '测试电脑A');
  console.log('✓ B 收到配对请求');

  const sasAP = once(A.node, 'pair:sas');
  const sasBP = once(B.node, 'pair:sas');
  B.node.acceptPair();
  const { sas: sasA } = await sasAP;
  const { sas: sasB } = await sasBP;
  assert.match(sasA, /^\d{6}$/);
  assert.equal(sasA, sasB, '双方 SAS 必须一致');
  console.log('✓ 双方算出一致的 SAS:', sasA);

  const doneA = once(A.node, 'pair:done');
  const doneB = once(B.node, 'pair:done');
  A.node.pairSasConfirm(true); // A 用户：一致
  B.node.pairSasConfirm(true); // B 用户：一致
  const dA = await doneA;
  const dB = await doneB;
  assert.equal(dA.deviceName, '测试电脑B');
  assert.equal(dB.deviceName, '测试电脑A');
  const kA = A.store.getPeer(dA.deviceId);
  const kB = B.store.getPeer(dB.deviceId);
  assert.ok(kA && kB, '双方应存下长期密钥');
  assert.equal(kA.keyB64, kB.keyB64, '双方长期密钥一致');
  console.log('✓ 双方确认 SAS，配对成功，长期密钥一致');

  await new Promise((r) => setTimeout(r, 800));

  // ---- 3. SAS 不一致取消 ----
  const incomingP2 = once(B.node, 'pair:incoming');
  await A.node.pairWith('127.0.0.1', PORT_B);
  await incomingP2;
  const sasAP2 = once(A.node, 'pair:sas');
  const sasBP2 = once(B.node, 'pair:sas');
  B.node.acceptPair();
  await sasAP2;
  await sasBP2;
  const failAP = once(A.node, 'pair:failed');
  const failBP = once(B.node, 'pair:failed');
  A.node.pairSasConfirm(true);
  B.node.pairSasConfirm(false); // B 用户：不一致
  const fA = await failAP;
  const fB = await failBP;
  assert.match(fA.reason + fB.reason, /不一致/);
  console.log('✓ SAS 不一致时双方取消配对');

  await new Promise((r) => setTimeout(r, 800));

  // ---- 4. 通话流程（enc 帧方向+序号保护） ----
  const incomingCallP = once(B.node, 'call:incoming');
  const acceptedP = once(A.node, 'call:accepted');
  await A.node.call('127.0.0.1', 'v=0 fake-offer-sdp', PORT_B);
  const inc = await incomingCallP;
  assert.equal(inc.sdp, 'v=0 fake-offer-sdp');
  console.log('✓ B 收到来电，Offer 经加密帧送达');
  B.node.answerCall('v=0 fake-answer-sdp');
  const acc = await acceptedP;
  assert.equal(acc.sdp, 'v=0 fake-answer-sdp');
  console.log('✓ A 收到接听，Answer 经加密帧送达');

  const iceP = once(B.node, 'call:ice');
  A.node.sendIce({ candidate: 'candidate:1 1 udp 123 192.168.1.2 5000 typ host' });
  const ice = await iceP;
  assert.equal(ice.candidate.candidate, 'candidate:1 1 udp 123 192.168.1.2 5000 typ host');
  console.log('✓ ICE 候选透传正常');

  const hangupP = once(B.node, 'call:hangup');
  const endedP = once(B.node, 'call:ended');
  A.node.hangup();
  await hangupP;
  const ended = await endedP;
  assert.equal(ended.reason, 'remote-hangup');
  console.log('✓ A 挂断，B 立即收到通知');

  await A.node.stop();
  await B.node.stop();
  fs.rmSync(A.dir, { recursive: true, force: true });
  fs.rmSync(B.dir, { recursive: true, force: true });
  console.log('\n全部信令集成测试通过 ✅');
}

main().catch((e) => {
  console.error('❌ 测试失败:', e);
  process.exit(1);
});

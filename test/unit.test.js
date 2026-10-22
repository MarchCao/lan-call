// LAN Call 单元测试 v2：协议 / 密码学 / 配对状态机 / enc 帧防护
// 运行：node --test test/unit.test.js
'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const proto = require('../src/common/protocol');
const cx = require('../src/common/crypto');
const { PairingSession, aStartAuth, bAnswerAuth, aVerifyAndFinish, bVerifyOk } = require('../src/core/pairing');

describe('protocol v2', () => {
  it('版本号为 2，IPv4 校验', () => {
    assert.equal(proto.PROTO_VERSION, 2);
    assert.equal(proto.isValidIpv4('192.168.1.20'), true);
    assert.equal(proto.isValidIpv4('999.1.1.1'), false);
  });
});

describe('crypto v2: ECDH + SAS', () => {
  it('双方 X25519 共享密钥一致', () => {
    const a = cx.generateEphemeralKeypair();
    const b = cx.generateEphemeralKeypair();
    const s1 = cx.x25519SharedSecret(a.privateKey, b.publicKey);
    const s2 = cx.x25519SharedSecret(b.privateKey, a.publicKey);
    assert.ok(s1.equals(s2));
    assert.equal(s1.length, 32);
  });

  it('非法公钥被拒绝', () => {
    const a = cx.generateEphemeralKeypair();
    assert.throws(() => cx.x25519SharedSecret(a.privateKey, Buffer.alloc(16)));
  });

  it('SAS 双方一致；中间人替换公钥则 SAS 不一致', () => {
    const a = cx.generateEphemeralKeypair();
    const b = cx.generateEphemeralKeypair();
    const idA = 'a';
    const idB = 'b';
    // 正常：双方算出相同 SAS
    const sAB = cx.x25519SharedSecret(a.privateKey, b.publicKey);
    const sBA = cx.x25519SharedSecret(b.privateKey, a.publicKey);
    const tA = cx.buildTranscript(a.publicKey, b.publicKey, idA, idB);
    const tB = cx.buildTranscript(a.publicKey, b.publicKey, idA, idB);
    assert.equal(cx.deriveSasCode(sAB, tA), cx.deriveSasCode(sBA, tB));

    // MITM：攻击者用自己的密钥对分别与 A/B 建连
    const m = cx.generateEphemeralKeypair();
    const sAM = cx.x25519SharedSecret(a.privateKey, m.publicKey); // A 以为对端是 B
    const sMB = cx.x25519SharedSecret(m.privateKey, b.publicKey); // B 以为对端是 A
    const tAM = cx.buildTranscript(a.publicKey, m.publicKey, idA, idB);
    const tMB = cx.buildTranscript(m.publicKey, b.publicKey, idA, idB);
    const sasA = cx.deriveSasCode(sAM, tAM);
    const sasB = cx.deriveSasCode(sMB, tMB);
    assert.notEqual(sasA, sasB, 'MITM 下双方 SAS 必须不一致（用户可察觉）');
    assert.match(sasA, /^\d{6}$/);
  });

  it('长期配对密钥双方一致', () => {
    const a = cx.generateEphemeralKeypair();
    const b = cx.generateEphemeralKeypair();
    const s1 = cx.x25519SharedSecret(a.privateKey, b.publicKey);
    const s2 = cx.x25519SharedSecret(b.privateKey, a.publicKey);
    assert.ok(cx.deriveMasterKey(s1, 'a', 'b').equals(cx.deriveMasterKey(s2, 'a', 'b')));
  });

  it('配对确认 MAC 双向验证', () => {
    const k = cx.randomBytes(32);
    const t = Buffer.from('transcript');
    const macA = cx.makePairConfirmMac(k, 'a', t);
    const macB = cx.makePairConfirmMac(k, 'b', t);
    assert.ok(cx.safeEqual(macA, cx.makePairConfirmMac(k, 'a', t)));
    assert.ok(!cx.safeEqual(macA, macB), 'a/b 的 MAC 应不同（防反射）');
  });
});

describe('crypto v2: 会话密钥与 enc 帧防护', () => {
  function setup() {
    const master = cx.randomBytes(32);
    const nA = cx.randomBytes(16).toString('base64');
    const nB = cx.randomBytes(16).toString('base64');
    const { kAB, kBA } = cx.deriveSessionKeys(master, nA, nB);
    return { kAB, kBA };
  }

  it('双向密钥派生一致且方向隔离', () => {
    const { kAB, kBA } = setup();
    assert.equal(kAB.length, 32);
    assert.ok(!kAB.equals(kBA), '两方向密钥必须不同');
  });

  it('enc 帧加解密往返', () => {
    const { kAB } = setup();
    const f = cx.encryptFrame(kAB, 'a2b', 0, { type: 'ping' });
    assert.equal(f.dir, 'a2b');
    assert.equal(f.seq, 0);
    const r = cx.decryptFrame(kAB, f, 'a2b', 0);
    assert.ok(r.ok);
    assert.deepEqual(r.plaintext, { type: 'ping' });
  });

  it('重放攻击被拒绝（同一序号第二次）', () => {
    const { kAB } = setup();
    const f = cx.encryptFrame(kAB, 'a2b', 7, { type: 'hangup' });
    assert.ok(cx.decryptFrame(kAB, f, 'a2b', 7).ok);
    const replay = cx.decryptFrame(kAB, f, 'a2b', 8); // 序号已推进，重放旧帧
    assert.ok(!replay.ok);
    assert.match(replay.reason, /重放/);
  });

  it('反射攻击被拒绝（a2b 帧喂给 b2a 方向）', () => {
    const { kAB, kBA } = setup();
    const f = cx.encryptFrame(kAB, 'a2b', 0, { type: 'call-request' });
    const r = cx.decryptFrame(kBA, f, 'b2a', 0);
    assert.ok(!r.ok);
    assert.match(r.reason, /反射/);
  });

  it('序号跳跃被拒绝', () => {
    const { kAB } = setup();
    const f = cx.encryptFrame(kAB, 'a2b', 5, { type: 'ping' });
    const r = cx.decryptFrame(kAB, f, 'a2b', 3);
    assert.ok(!r.ok);
  });

  it('篡改密文解密失败', () => {
    const { kAB } = setup();
    const f = cx.encryptFrame(kAB, 'a2b', 0, { type: 'ping' });
    const t = Buffer.from(f.ct, 'base64');
    t[0] ^= 0xff;
    f.ct = t.toString('base64');
    assert.ok(!cx.decryptFrame(kAB, f, 'a2b', 0).ok);
  });
});

describe('pairing v2 状态机：ECDH + SAS 双方确认', () => {
  function fullHandshake() {
    const { session: sA, send } = PairingSession.startAsA({ ownId: 'a', ownName: 'A电脑' });
    const sB = PairingSession.startAsB({ ownId: 'b', msg: send });
    const { send: pubB, sas: sasB } = sB.bAccept();
    const rA = sA.handleMessage(pubB);
    return { sA, sB, sasA: rA.sas, sasB };
  }

  it('完整配对成功：SAS 一致，双方密钥一致', () => {
    const { sA, sB, sasA, sasB } = fullHandshake();
    assert.match(sasA, /^\d{6}$/);
    assert.equal(sasA, sasB, '双方 SAS 必须一致');

    const cA = sA.confirmSas(); // A 用户确认
    const cB = sB.confirmSas(); // B 用户确认
    const dA = sA.handleMessage(cB.send);
    const dB = sB.handleMessage(cA.send);
    assert.ok(dA.done, 'A 应完成');
    assert.ok(dB.done, 'B 应完成');
    assert.ok(dA.key.equals(dB.key), '双方长期密钥一致');
    assert.equal(dA.key.length, 32);
  });

  it('对方先确认也能完成（deferred 路径）', () => {
    const { sA, sB, sasA, sasB } = fullHandshake();
    assert.equal(sasA, sasB);
    const cB = sB.confirmSas(); // B 先确认
    const rA1 = sA.handleMessage(cB.send); // A 还没点确认 → 缓存
    assert.ok(rA1.deferred);
    assert.ok(!rA1.done);
    const cA = sA.confirmSas(); // A 再确认 → 立即完成
    assert.ok(cA.done);
    assert.ok(cA.key.equals(sB.masterKey));
    const dB = sB.handleMessage(cA.send);
    assert.ok(dB.done);
    assert.ok(dB.key.equals(cA.key));
  });

  it('SAS 不一致时取消', () => {
    const { sA, sB } = fullHandshake();
    const abort = sA.abort('sas-mismatch');
    const r = sB.handleMessage(abort);
    assert.ok(r.failed);
  });

  it('中间人即使骗过 SAS 比对，confirm MAC 也会失败', () => {
    // 模拟：攻击者替换了 B 的公钥，但用户没发现 SAS 不一致而点了确认
    const { session: sA, send } = PairingSession.startAsA({ ownId: 'a', ownName: 'A' });
    const evil = cx.generateEphemeralKeypair();
    const tampered = { ...send, ephPubA: send.ephPubA }; // A 的请求正常
    const sB = PairingSession.startAsB({ ownId: 'b', msg: tampered });
    const { send: pubB } = sB.bAccept();
    // 攻击者把 B 的公钥换成自己的
    const evilPubB = { ...pubB, ephPubB: evil.publicKey.toString('base64') };
    const rA = sA.handleMessage(evilPubB);
    assert.ok(rA.sas, 'A 算出 SAS（与 B 的不同，但假设用户没核对）');
    const cA = sA.confirmSas();
    const cB = sB.confirmSas();
    // B 用真密钥算的 mac，A 用被污染的密钥验 → 失败
    const dA = sA.handleMessage(cB.send);
    assert.ok(dA.failed, 'MAC 验证必须失败');
    assert.match(dA.failed, /中间人/);
  });
});

describe('会话认证（K_master 双向认证）', () => {
  it('完整认证成功；密钥不匹配失败；重放失败', () => {
    const key = cx.randomBytes(32);
    const { nonceA } = aStartAuth();
    const { nonceB, macB } = bAnswerAuth({ key, ownId: 'b', peerId: 'a', nonceA });
    const res = aVerifyAndFinish({ key, ownId: 'a', peerId: 'b', nonceA, nonceB, macB });
    assert.ok(res.ok);
    assert.ok(bVerifyOk({ key, ownId: 'b', peerId: 'a', nonceA, nonceB, macA: res.macA }));

    const wrong = cx.randomBytes(32);
    const res2 = aVerifyAndFinish({ key: wrong, ownId: 'a', peerId: 'b', nonceA, nonceB, macB });
    assert.ok(!res2.ok);

    const { nonceA: nA2 } = aStartAuth();
    const res3 = aVerifyAndFinish({ key, ownId: 'a', peerId: 'b', nonceA: nA2, nonceB, macB });
    assert.ok(!res3.ok, 'nonce 重放应失败');
  });
});

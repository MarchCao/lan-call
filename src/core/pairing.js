// LAN Call 配对/认证状态机 v2 —— 纯逻辑，不依赖传输层与平台 API
// 配对：X25519 ECDH + SAS 双方屏幕比对 + 双向 pair-confirm（防 MITM/离线穷举）
// A = 配对发起方；B = 配对接收方。

'use strict';

const { MsgType } = require('../common/protocol');
const cx = require('../common/crypto');

const PairState = Object.freeze({
  IDLE: 'idle',
  A_WAIT_PUBKEY: 'a-wait-pubkey',   // A: 已发 pair-request，等 B 的 pair-pubkey
  A_WAIT_USER: 'a-wait-user',       // A: 已算出 SAS，等本端用户比对确认
  A_WAIT_B_CONFIRM: 'a-wait-b-confirm', // A: 已发 pair-confirm，等 B 的 pair-confirm
  B_WAIT_ACCEPT: 'b-wait-accept',    // B: 收到 pair-request，等本端用户接受/拒绝
  B_WAIT_USER: 'b-wait-user',       // B: 已发 pair-pubkey，等本端用户比对确认
  B_WAIT_A_CONFIRM: 'b-wait-a-confirm', // B: 已发 pair-confirm，等 A 的 pair-confirm
  PAIRED: 'paired',
  FAILED: 'failed',
});

class PairingSession {
  constructor({ role, ownId, peerId, peerName }) {
    this.role = role; // 'a' | 'b'
    this.ownId = ownId;
    this.peerId = peerId || null;
    this.peerName = peerName || '';
    this.eph = null;      // { publicKey, privateKey }
    this.peerPub = null;  // Buffer(32)
    this.shared = null;   // S
    this.transcript = null;
    this.masterKey = null;
    this.sas = null;
    this.state = PairState.IDLE;
    this._confirmedMacSent = false;
  }

  // ---- A 端：开始配对 ----
  static startAsA({ ownId, ownName }) {
    const s = new PairingSession({ role: 'a', ownId });
    s.eph = cx.generateEphemeralKeypair();
    s.state = PairState.A_WAIT_PUBKEY;
    return {
      session: s,
      send: {
        type: MsgType.PAIR_REQUEST,
        deviceId: ownId,
        deviceName: ownName,
        ephPubA: s.eph.publicKey.toString('base64'),
      },
    };
  }

  // ---- B 端：收到 pair-request ----
  static startAsB({ ownId, msg }) {
    const s = new PairingSession({
      role: 'b',
      ownId,
      peerId: msg.deviceId,
      peerName: msg.deviceName || '',
    });
    s.peerPub = Buffer.from(msg.ephPubA, 'base64');
    if (s.peerPub.length !== 32) throw new Error('pairing: 对方临时公钥非法');
    s.state = PairState.B_WAIT_ACCEPT;
    return s;
  }

  // ---- B 端：用户接受配对请求 ----
  // 返回 { send: pair-pubkey, sas }，sas 显示给本端用户
  bAccept() {
    if (this.role !== 'b' || this.state !== PairState.B_WAIT_ACCEPT) {
      throw new Error('pairing: 非法的 B 端接受时机');
    }
    this.eph = cx.generateEphemeralKeypair();
    this._deriveAll();
    this.state = PairState.B_WAIT_USER;
    return {
      sas: this.sas,
      send: {
        type: MsgType.PAIR_PUBKEY,
        deviceId: this.ownId,
        ephPubB: this.eph.publicKey.toString('base64'),
      },
    };
  }

  // 由 A/B 两端在拿到双方公钥后调用
  _deriveAll() {
    const ephPubA = this.role === 'a' ? this.eph.publicKey : this.peerPub;
    const ephPubB = this.role === 'a' ? this.peerPub : this.eph.publicKey;
    const idA = this.role === 'a' ? this.ownId : this.peerId;
    const idB = this.role === 'a' ? this.peerId : this.ownId;
    this.shared = cx.x25519SharedSecret(this.eph.privateKey, this.peerPub);
    this.transcript = cx.buildTranscript(ephPubA, ephPubB, idA, idB);
    this.masterKey = cx.deriveMasterKey(this.shared, idA, idB);
    this.sas = cx.deriveSasCode(this.shared, this.transcript);
  }

  // ---- 本端用户确认 SAS 一致 ----
  // 返回要发送的 pair-confirm；若对方的 confirm 已先到，立即验证并完成
  confirmSas() {
    if (
      (this.role === 'a' && this.state !== PairState.A_WAIT_USER) ||
      (this.role === 'b' && this.state !== PairState.B_WAIT_USER)
    ) {
      throw new Error('pairing: 非法的 SAS 确认时机');
    }
    const mac = cx.makePairConfirmMac(this.masterKey, this.role, this.transcript);
    this.state = this.role === 'a' ? PairState.A_WAIT_B_CONFIRM : PairState.B_WAIT_A_CONFIRM;
    const send = { type: MsgType.PAIR_CONFIRM, mac: mac.toString('base64') };
    if (this._deferredPeerMac) {
      // 对方先确认：现在验证
      const peerRole = this.role === 'a' ? 'b' : 'a';
      const expected = cx.makePairConfirmMac(this.masterKey, peerRole, this.transcript);
      if (!cx.safeEqual(expected.toString('base64'), this._deferredPeerMac)) {
        this._wipe();
        this.state = PairState.FAILED;
        return { send, failed: '对方确认 MAC 验证失败（疑似中间人攻击）' };
      }
      this.state = PairState.PAIRED;
      const key = this.masterKey;
      this._wipeEphemeral();
      return { send, done: true, key, followUp: { type: MsgType.PAIR_DONE } };
    }
    return { send };
  }

  // ---- 处理对端消息 ----
  handleMessage(msg) {
    if (msg.type === MsgType.PAIR_ABORT) {
      this._wipe();
      this.state = PairState.FAILED;
      return { failed: '对方取消了配对' };
    }
    if (msg.type === MsgType.PAIR_DONE) {
      return { ignored: true }; // 对端的完成回执
    }
    if (this.role === 'a') return this._aHandle(msg);
    return this._bHandle(msg);
  }

  _aHandle(msg) {
    if (msg.type === MsgType.PAIR_PUBKEY && this.state === PairState.A_WAIT_PUBKEY) {
      this.peerId = msg.deviceId || this.peerId;
      this.peerPub = Buffer.from(msg.ephPubB, 'base64');
      if (this.peerPub.length !== 32) {
        this.state = PairState.FAILED;
        return { failed: '对方临时公钥非法' };
      }
      this._deriveAll();
      this.state = PairState.A_WAIT_USER;
      return { sas: this.sas };
    }
    if (
      msg.type === MsgType.PAIR_CONFIRM &&
      (this.state === PairState.A_WAIT_B_CONFIRM || this.state === PairState.A_WAIT_USER)
    ) {
      if (this.state === PairState.A_WAIT_USER) {
        // 对方先确认：缓存，等本端用户比对 SAS 后再验证
        this._deferredPeerMac = msg.mac;
        return { deferred: true };
      }
      return this._verifyPeerConfirm('b', msg.mac);
    }
    return { failed: `A 端收到意外消息: ${msg.type}` };
  }

  _bHandle(msg) {
    if (
      msg.type === MsgType.PAIR_CONFIRM &&
      (this.state === PairState.B_WAIT_A_CONFIRM || this.state === PairState.B_WAIT_USER)
    ) {
      if (this.state === PairState.B_WAIT_USER) {
        this._deferredPeerMac = msg.mac;
        return { deferred: true };
      }
      return this._verifyPeerConfirm('a', msg.mac);
    }
    return { failed: `B 端收到意外消息: ${msg.type}` };
  }

  _verifyPeerConfirm(peerRole, macB64) {
    const expected = cx.makePairConfirmMac(this.masterKey, peerRole, this.transcript);
    if (!cx.safeEqual(expected.toString('base64'), macB64)) {
      this._wipe();
      this.state = PairState.FAILED;
      return { failed: '对方确认 MAC 验证失败（疑似中间人攻击）' };
    }
    this.state = PairState.PAIRED;
    const key = this.masterKey;
    this._wipeEphemeral();
    return { done: true, key, send: { type: MsgType.PAIR_DONE } };
  }

  abort(reason) {
    this._wipe();
    this.state = PairState.FAILED;
    return { type: MsgType.PAIR_ABORT, reason: reason || 'cancelled' };
  }

  _wipeEphemeral() {
    // 擦除临时私钥与共享密钥；masterKey 保留给调用方存储
    this.eph = null;
    this.shared = null;
    this.masterKey = null;
  }

  _wipe() {
    this._wipeEphemeral();
    this.sas = null;
    this.transcript = null;
  }
}

// ---- 已配对设备的会话认证（每次建连双向认证，密钥为 K_master） ----
function aStartAuth() {
  return { nonceA: cx.randomBytes(16).toString('base64') };
}
function bAnswerAuth({ key, ownId, peerId, nonceA }) {
  const nonceB = cx.randomBytes(16).toString('base64');
  const macB = cx.makeAuthMacB(key, nonceA, nonceB, peerId, ownId);
  return { nonceB, macB: macB.toString('base64') };
}
function aVerifyAndFinish({ key, ownId, peerId, nonceA, nonceB, macB }) {
  const expected = cx.makeAuthMacB(key, nonceA, nonceB, ownId, peerId);
  if (!cx.safeEqual(expected.toString('base64'), macB)) return { ok: false };
  const macA = cx.makeAuthMacA(key, nonceA, nonceB, ownId, peerId);
  return { ok: true, macA: macA.toString('base64') };
}
function bVerifyOk({ key, ownId, peerId, nonceA, nonceB, macA }) {
  const expected = cx.makeAuthMacA(key, nonceA, nonceB, peerId, ownId);
  return cx.safeEqual(expected.toString('base64'), macA);
}

module.exports = {
  PairState,
  PairingSession,
  aStartAuth,
  bAnswerAuth,
  aVerifyAndFinish,
  bVerifyOk,
};

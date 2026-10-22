// LAN Call 信令层 v2 —— WebSocket 服务端 + 客户端（主进程）
// 配对：X25519 ECDH + SAS 双方比对 + 双向 pair-confirm（协议 v2）
// 会话：每次建连双向认证 → HKDF 派生双向会话密钥 → enc 帧方向+序号 AAD
// 暴露面收敛：maxPayload 256KB、未认证连接上限、配对请求限流、握手超时、
//            配对确认尝试上限。

'use strict';

const { EventEmitter } = require('events');
const WebSocket = require('ws');
const { listLanIpv4 } = require('./netutil');
const { PROTO_VERSION, DEFAULT_PORT, MsgType, InnerType } = require('../common/protocol');
const cx = require('../common/crypto');
const {
  PairingSession,
  aStartAuth,
  bAnswerAuth,
  aVerifyAndFinish,
  bVerifyOk,
} = require('../core/pairing');

const HELLO_TIMEOUT_MS = 10_000;
const HANDSHAKE_TIMEOUT_MS = 20_000; // 建连后 20s 内必须完成认证（或进入配对）
const PAIR_TIMEOUT_MS = 120_000;
const PING_INTERVAL_MS = 30_000;
const PONG_TIMEOUT_MS = 60_000;
const MAX_PAYLOAD = 256 * 1024; // SDP/ICE 帧远小于此值；防超大帧内存攻击
const MAX_UNAUTH_CONNECTIONS = 16;
const PAIR_REQ_PER_MIN_PER_IP = 5;
const PAIR_CONFIRM_MAX_ATTEMPTS = 3;
const PAIR_ABUSE_COOLDOWN_MS = 60_000;

function sendJson(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

class SignalingNode extends EventEmitter {
  constructor({ store, port = DEFAULT_PORT }) {
    super();
    this.store = store;
    this.port = port;
    this.servers = [];
    this.activeCall = null;
    this.pendingPairB = null; // { ws, session }
    this._unauthCount = 0;
    this._pairReqLog = new Map(); // ip -> { count, windowStart }
    this._abuseCooldown = new Map(); // ip -> until
    this._pingTimer = null;
  }

  getInfo() {
    return {
      deviceId: this.store.data.ownId,
      deviceName: this.store.data.deviceName,
      ips: listLanIpv4(),
      port: this.port,
      pairedDevices: this.store.listPeers(),
      storeMode: this.store.mode,
      protoVersion: PROTO_VERSION,
    };
  }

  setDeviceName(name) {
    this.store.data.deviceName = String(name).slice(0, 40);
    this.store.save();
  }

  // ---------- 服务端 ----------
  async start() {
    const addrs = listLanIpv4();
    const bindAddrs = addrs.length
      ? addrs.map((a) => a.address)
      : (process.env.LAN_CALL_ALLOW_LOOPBACK ? ['127.0.0.1'] : []);
    if (!bindAddrs.length) {
      throw new Error('未找到局域网 IPv4 地址，无法启动信令服务');
    }
    for (const addr of bindAddrs) {
      const wss = new WebSocket.Server({ host: addr, port: this.port, maxPayload: MAX_PAYLOAD });
      wss.on('connection', (ws, req) => this._onServerConnection(ws, req));
      await new Promise((resolve, reject) => {
        wss.on('listening', resolve);
        wss.on('error', reject);
      });
      this.servers.push(wss);
    }
    this._pingTimer = setInterval(() => this._pingAll(), PING_INTERVAL_MS);
    return bindAddrs;
  }

  async stop() {
    clearInterval(this._pingTimer);
    for (const wss of this.servers) {
      await new Promise((r) => wss.close(r));
    }
    this.servers = [];
  }

  // ---------- 客户端：配对（A 端） ----------
  async pairWith(ip, port = this.port) {
    const ws = await this._connect(ip, port);
    const sess = {
      ws, role: 'client', authed: false, key: null,
      peerId: null, peerName: '', helloDone: false,
      pairingIntent: true, pairIp: ip,
      confirmAttempts: 0,
    };
    ws._sess = sess;
    this._armHandshakeTimer(sess);
    sess.pairTimer = setTimeout(() => this._failPair(sess, '配对超时（120 秒）'), PAIR_TIMEOUT_MS);
  }

  // ---------- 客户端：通话（A 端，需已配对） ----------
  async call(ip, offerSdp, port = this.port) {
    if (this.activeCall) throw new Error('当前已有通话进行中');
    const ws = await this._connect(ip, port);
    const sess = {
      ws, role: 'client', authed: false, key: null,
      peerId: null, peerName: '', pendingOffer: offerSdp,
    };
    ws._sess = sess;
    this._armHandshakeTimer(sess);
  }

  // ---------- B 端：配对响应 ----------
  acceptPair() {
    const p = this.pendingPairB;
    if (!p) throw new Error('没有待处理的配对请求');
    const { send, sas } = p.session.bAccept();
    sendJson(p.ws, send);
    this.emit('pair:sas', { sas, deviceId: p.session.peerId, deviceName: p.session.peerName });
  }

  rejectPair() {
    const p = this.pendingPairB;
    if (!p) return;
    sendJson(p.ws, p.session.abort('declined'));
    try { p.ws.close(); } catch { /* ignore */ }
    this.pendingPairB = null;
  }

  // 本端用户比对 SAS 后确认（ok=true 一致 / false 不一致取消）
  pairSasConfirm(ok) {
    const sess = this._findPairingSession();
    if (!sess || !sess.pairing) throw new Error('没有进行中的配对');
    if (!ok) {
      const msg = sess.pairing.abort('sas-mismatch');
      sendJson(sess.ws, msg);
      this._cleanupPairing(sess, '双方校验码不一致，已取消配对');
      return;
    }
    const r = sess.pairing.confirmSas();
    if (r.send) sendJson(sess.ws, r.send);
    if (r.followUp) sendJson(sess.ws, r.followUp);
    if (r.failed) {
      this._cleanupPairing(sess, r.failed);
      return;
    }
    if (r.done) {
      // 对方已先确认：本端确认后立即完成
      if (sess.isB) this._pairDoneB(sess, r.key);
      else this._completePairingA(sess, r.key);
    }
    // 否则等待对方的 pair-confirm
  }

  _findPairingSession() {
    if (this.pendingPairB && this.pendingPairB.ws._sess) {
      const raw = this.pendingPairB.ws._sess;
      raw.isB = true;
      return raw;
    }
    if (this._clientPairSess && this._clientPairSess.ws._sess) {
      const raw = this._clientPairSess.ws._sess;
      raw.isB = false;
      return raw;
    }
    return null;
  }

  _completePairingA(sess, key) {
    clearTimeout(sess.pairTimer);
    this._disarmHandshakeTimer(sess);
    this.store.addPeer(sess.pairing.peerId, sess.peerName, key);
    const info = { deviceId: sess.pairing.peerId, deviceName: sess.peerName };
    sess.pairing = null;
    this._clientPairSess = null;
    this.emit('pair:done', info);
    setTimeout(() => { try { sess.ws.close(); } catch { /* ignore */ } }, 500);
  }

  // ---------- 通话控制 ----------
  answerCall(answerSdp) {
    const c = this.activeCall;
    if (!c || c.dir !== 'in') throw new Error('没有待接听的来电');
    this._sendInner(c.ws, InnerType.CALL_ACCEPT, { sdp: answerSdp });
    c.state = 'active';
  }

  rejectCall(reason = 'declined') {
    const c = this.activeCall;
    if (!c || c.dir !== 'in') return;
    this._sendInner(c.ws, InnerType.CALL_REJECT, { reason });
    this._endCall('rejected');
  }

  sendIce(candidate) {
    const c = this.activeCall;
    if (!c || !(c.state === 'active' || c.state === 'dialing')) return;
    this._sendInner(c.ws, InnerType.ICE, { candidate });
  }

  hangup() {
    const c = this.activeCall;
    if (!c) return;
    try {
      this._sendInner(c.ws, InnerType.HANGUP, {});
    } catch { /* 对端可能已断开 */ }
    this._endCall('local-hangup');
  }

  // ================= 内部实现 =================

  _peerIp(ws) {
    try {
      return ws._socket.remoteAddress || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  _armHandshakeTimer(sess) {
    clearTimeout(sess.handshakeTimer);
    sess.handshakeTimer = setTimeout(() => {
      if (!sess.authed && !sess.pairing) {
        try { sess.ws.close(); } catch { /* ignore */ }
      }
    }, HANDSHAKE_TIMEOUT_MS);
  }

  _disarmHandshakeTimer(sess) {
    clearTimeout(sess.handshakeTimer);
  }

  _checkPairRateLimit(ip) {
    const now = Date.now();
    const cd = this._abuseCooldown.get(ip);
    if (cd && now < cd) return false;
    const e = this._pairReqLog.get(ip) || { count: 0, windowStart: now };
    if (now - e.windowStart > 60_000) {
      e.count = 0;
      e.windowStart = now;
    }
    e.count += 1;
    this._pairReqLog.set(ip, e);
    return e.count <= PAIR_REQ_PER_MIN_PER_IP;
  }

  _connect(ip, port = this.port) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://${ip}:${port}`, { maxPayload: MAX_PAYLOAD });
      const timer = setTimeout(() => {
        ws.terminate();
        reject(new Error(`连接 ${ip}:${port} 超时（对方可能未运行软件或被防火墙拦截）`));
      }, 8000);
      ws.on('open', () => {
        clearTimeout(timer);
        sendJson(ws, {
          type: MsgType.HELLO,
          v: PROTO_VERSION,
          deviceId: this.store.data.ownId,
          deviceName: this.store.data.deviceName,
        });
        ws.on('message', (d) => this._onClientMessage(ws, d));
        ws.on('close', () => this._onWsClose(ws));
        ws.on('error', () => {});
        resolve(ws);
      });
      ws.on('error', (e) => {
        clearTimeout(timer);
        reject(new Error(`无法连接到 ${ip}:${port}：${e.message}`));
      });
    });
  }

  _onServerConnection(ws, req) {
    if (this._unauthCount >= MAX_UNAUTH_CONNECTIONS) {
      try { ws.close(1013, 'too many unauthenticated connections'); } catch { /* ignore */ }
      return;
    }
    this._unauthCount += 1;
    const sess = {
      ws, role: 'server', authed: false, key: null,
      peerId: null, peerName: '', helloDone: false,
      confirmAttempts: 0,
      ip: (req && req.socket && req.socket.remoteAddress) || 'unknown',
    };
    ws._sess = sess;
    ws._helloTimer = setTimeout(() => { try { ws.close(); } catch { /* ignore */ } }, HELLO_TIMEOUT_MS);
    this._armHandshakeTimer(sess);
    ws.on('message', (d) => this._onServerMessage(ws, d));
    ws.on('close', () => this._onWsClose(ws));
    ws.on('error', () => {});
  }

  _handleHello(sess, msg) {
    if (msg.v !== PROTO_VERSION) {
      sendJson(sess.ws, { type: MsgType.PAIR_ABORT, reason: 'version-mismatch' });
      try { sess.ws.close(); } catch { /* ignore */ }
      return false;
    }
    sess.peerId = msg.deviceId;
    sess.peerName = msg.deviceName || '';
    sess.helloDone = true;
    clearTimeout(sess.ws._helloTimer);
    sendJson(sess.ws, {
      type: MsgType.HELLO,
      v: PROTO_VERSION,
      deviceId: this.store.data.ownId,
      deviceName: this.store.data.deviceName,
    });
    return true;
  }

  // ---- 服务端消息 ----
  _onServerMessage(ws, data) {
    const sess = ws._sess;
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch { return; }
    if (!sess.helloDone) {
      if (msg.type === MsgType.HELLO && this._handleHello(sess, msg)) return;
      try { ws.close(); } catch { /* ignore */ }
      return;
    }
    if (msg.type === MsgType.ENC && sess.authed) {
      this._onInnerMessage(sess, msg);
      return;
    }
    // 配对请求（B 端）
    if (msg.type === MsgType.PAIR_REQUEST && !sess.authed && !sess.pairing) {
      if (!this._checkPairRateLimit(sess.ip)) {
        sendJson(ws, { type: MsgType.PAIR_ABORT, reason: 'rate-limited' });
        try { ws.close(); } catch { /* ignore */ }
        return;
      }
      if (this.pendingPairB) {
        sendJson(ws, { type: MsgType.PAIR_ABORT, reason: 'busy' });
        try { ws.close(); } catch { /* ignore */ }
        return;
      }
      try {
        const session = PairingSession.startAsB({ ownId: this.store.data.ownId, msg });
        sess.pairing = session;
        this.pendingPairB = { ws, session };
        this._disarmHandshakeTimer(sess); // 进入配对流程，改用配对超时
        sess.pairTimer = setTimeout(() => this._failPairB('配对超时（120 秒）'), PAIR_TIMEOUT_MS);
        this.emit('pair:incoming', { deviceId: session.peerId, deviceName: session.peerName });
      } catch (e) {
        sendJson(ws, { type: MsgType.PAIR_ABORT, reason: 'bad-request' });
        try { ws.close(); } catch { /* ignore */ }
      }
      return;
    }
    // 会话认证（B 端）
    if (msg.type === MsgType.AUTH_CHALLENGE && !sess.authed && !sess.pairing) {
      const peer = this.store.getPeer(sess.peerId);
      if (!peer) { try { ws.close(); } catch { /* ignore */ } return; }
      const key = Buffer.from(peer.keyB64, 'base64');
      sess.key = key;
      sess._nonceA = msg.nonceA;
      const { nonceB, macB } = bAnswerAuth({
        key, ownId: this.store.data.ownId, peerId: sess.peerId, nonceA: msg.nonceA,
      });
      sess._nonceB = nonceB;
      sendJson(ws, { type: MsgType.AUTH_RESPONSE, deviceId: this.store.data.ownId, nonceB, macB });
      return;
    }
    if (msg.type === MsgType.AUTH_OK && sess.key && !sess.authed && !sess.pairing) {
      const ok = bVerifyOk({
        key: sess.key, ownId: this.store.data.ownId, peerId: sess.peerId,
        nonceA: sess._nonceA, nonceB: sess._nonceB, macA: msg.macA,
      });
      if (!ok) { try { ws.close(); } catch { /* ignore */ } return; }
      this._establishSession(sess, 'server');
      return;
    }
    // 配对进行中的消息（B 端）
    if (sess.pairing) {
      const r = sess.pairing.handleMessage(msg);
      if (r.sas) {
        // B 端不会在此收到 sas（sas 由 bAccept 本地产生）
      }
      if (r.send) sendJson(ws, r.send);
      if (r.done) this._pairDoneB(sess, r.key);
      else if (r.failed) {
        sess.confirmAttempts += 1;
        if (sess.confirmAttempts >= PAIR_CONFIRM_MAX_ATTEMPTS) {
          this._abuseCooldown.set(sess.ip, Date.now() + PAIR_ABUSE_COOLDOWN_MS);
        }
        this._failPairB(r.failed);
      }
      return;
    }
    if (msg.type === MsgType.PAIR_ABORT) {
      this._failPairB('对方取消了配对');
    }
  }

  // ---- 客户端消息 ----
  _onClientMessage(ws, data) {
    const sess = ws._sess;
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch { return; }
    if (!sess.helloDone) {
      if (msg.type === MsgType.HELLO && this._handleHello(sess, msg)) {
        this._afterClientHello(sess);
      } else { try { ws.close(); } catch { /* ignore */ } }
      return;
    }
    if (msg.type === MsgType.ENC && sess.authed) {
      this._onInnerMessage(sess, msg);
      return;
    }
    // 配对进行中（A 端）
    if (sess.pairing) {
      const r = sess.pairing.handleMessage(msg);
      if (r.sas) {
        this.emit('pair:sas', { sas: r.sas, deviceId: sess.pairing.peerId, deviceName: sess.peerName });
      }
      if (r.send) sendJson(ws, r.send);
      if (r.followUp) sendJson(ws, r.followUp);
      if (r.done) {
        this._completePairingA(sess, r.key);
      } else if (r.failed) {
        sess.confirmAttempts = (sess.confirmAttempts || 0) + 1;
        this._failPair(sess, r.failed);
      } else if (r.ignored) {
        // pair-done 回执，无操作
      }
      return;
    }
    // 会话认证（A 端）
    if (msg.type === MsgType.AUTH_RESPONSE && sess._nonceA && !sess.authed) {
      const res = aVerifyAndFinish({
        key: sess.key, ownId: this.store.data.ownId, peerId: sess.peerId,
        nonceA: sess._nonceA, nonceB: msg.nonceB, macB: msg.macB,
      });
      if (!res.ok) {
        this.emit('call:failed', { reason: '对方身份验证失败（密钥不匹配）' });
        try { ws.close(); } catch { /* ignore */ }
        return;
      }
      sess._nonceB = msg.nonceB;
      sendJson(ws, { type: MsgType.AUTH_OK, macA: res.macA });
      this._establishSession(sess, 'client');
      return;
    }
    if (msg.type === MsgType.PAIR_ABORT) {
      this._failPair(sess, '对方取消了配对');
    }
  }

  _afterClientHello(sess) {
    if (sess.pairingIntent && !sess.pairing) {
      const { session, send } = PairingSession.startAsA({
        ownId: this.store.data.ownId,
        ownName: this.store.data.deviceName,
      });
      sess.pairing = session;
      this._clientPairSess = { ws: sess.ws, pairing: session, isB: false };
      this._disarmHandshakeTimer(sess); // 进入配对流程，改用配对超时
      sendJson(sess.ws, send);
      return;
    }
    if (sess.pairing) return;
    const peer = this.store.getPeer(sess.peerId);
    if (!peer) {
      this.emit('call:failed', { reason: `未与该设备配对（${sess.peerName || sess.peerId}），请先完成配对` });
      try { sess.ws.close(); } catch { /* ignore */ }
      return;
    }
    sess.key = Buffer.from(peer.keyB64, 'base64');
    sess.peerName = peer.deviceName;
    const { nonceA } = aStartAuth();
    sess._nonceA = nonceA;
    sendJson(sess.ws, { type: MsgType.AUTH_CHALLENGE, nonceA });
  }

  // 认证完成：派生双向会话密钥
  _establishSession(sess, side) {
    const { kAB, kBA } = cx.deriveSessionKeys(sess.key, sess._nonceA, sess._nonceB);
    if (side === 'client') {
      // 本端是 A（发起方）：发送用 kAB，接收用 kBA
      sess.kSend = kAB; sess.kRecv = kBA;
      sess.sendDir = 'a2b'; sess.recvDir = 'b2a';
    } else {
      sess.kSend = kBA; sess.kRecv = kAB;
      sess.sendDir = 'b2a'; sess.recvDir = 'a2b';
    }
    sess.seqSend = 0;
    sess.seqRecv = 0;
    sess.authed = true;
    sess.lastPong = Date.now();
    this._disarmHandshakeTimer(sess);
    this._unauthCount = Math.max(0, this._unauthCount - 1);
    if (side === 'client' && sess.pendingOffer) {
      this.activeCall = { ws: sess.ws, peerId: sess.peerId, peerName: sess.peerName, dir: 'out', state: 'dialing' };
      this._sendInner(sess.ws, InnerType.CALL_REQUEST, { sdp: sess.pendingOffer });
      sess.pendingOffer = null;
    }
  }

  // ---- 加密内层消息（方向+序号 AAD） ----
  _sendInner(ws, type, payload) {
    const sess = ws._sess;
    if (!sess || !sess.authed || !sess.kSend) throw new Error('信道未建立');
    const frame = cx.encryptFrame(sess.kSend, sess.sendDir, sess.seqSend++, { type, ...payload });
    sendJson(ws, { type: MsgType.ENC, ...frame });
  }

  _onInnerMessage(sess, envelope) {
    const res = cx.decryptFrame(sess.kRecv, envelope, sess.recvDir, sess.seqRecv);
    if (!res.ok) {
      // 重放/反射/篡改：立即断开并告警
      this.emit('security:alert', { reason: res.reason, peerId: sess.peerId });
      try { sess.ws.close(); } catch { /* ignore */ }
      if (this.activeCall && this.activeCall.ws === sess.ws) {
        this.activeCall = null;
        this.emit('call:ended', { reason: 'security-violation' });
      }
      return;
    }
    sess.seqRecv += 1;
    const inner = res.plaintext;
    const ws = sess.ws;
    switch (inner.type) {
      case InnerType.CALL_REQUEST: {
        if (this.activeCall) {
          this._sendInner(ws, InnerType.CALL_REJECT, { reason: 'busy' });
          try { ws.close(); } catch { /* ignore */ }
          break;
        }
        this.activeCall = { ws, peerId: sess.peerId, peerName: sess.peerName, dir: 'in', state: 'ringing' };
        this.emit('call:incoming', { deviceId: sess.peerId, deviceName: sess.peerName, sdp: inner.sdp });
        break;
      }
      case InnerType.CALL_ACCEPT:
        if (this.activeCall && this.activeCall.dir === 'out') {
          this.activeCall.state = 'active';
          this.emit('call:accepted', { sdp: inner.sdp });
        }
        break;
      case InnerType.CALL_REJECT:
        if (this.activeCall && this.activeCall.dir === 'out') {
          const reason = inner.reason || 'declined';
          this._endCall('rejected');
          this.emit('call:rejected', { reason });
        }
        break;
      case InnerType.ICE:
        this.emit('call:ice', { candidate: inner.candidate });
        break;
      case InnerType.HANGUP:
        this._endCall('remote-hangup');
        this.emit('call:hangup', {});
        break;
      case InnerType.PING:
        this._sendInner(ws, InnerType.PONG, {});
        break;
      case InnerType.PONG:
        sess.lastPong = Date.now();
        break;
      default:
        break;
    }
  }

  _endCall(reason) {
    const c = this.activeCall;
    this.activeCall = null;
    if (c) {
      try { c.ws.close(); } catch { /* ignore */ }
      if (reason === 'remote-hangup' || reason === 'connection-lost' || reason === 'security-violation') {
        this.emit('call:ended', { reason });
      }
    }
  }

  _onWsClose(ws) {
    const sess = ws._sess;
    if (!sess) return;
    clearTimeout(sess.pairTimer);
    clearTimeout(sess.handshakeTimer);
    clearTimeout(ws._helloTimer);
    if (!sess.authed && !sess.pairing) {
      this._unauthCount = Math.max(0, this._unauthCount - 1);
    }
    if (this.activeCall && this.activeCall.ws === ws) {
      const wasRinging = this.activeCall.state === 'ringing' || this.activeCall.state === 'dialing';
      this.activeCall = null;
      this.emit('call:ended', { reason: wasRinging ? 'cancelled' : 'connection-lost' });
    }
    if (this.pendingPairB && this.pendingPairB.ws === ws) {
      this.pendingPairB = null;
      this.emit('pair:failed', { reason: '连接中断' });
    }
    if (this._clientPairSess && this._clientPairSess.ws === ws) {
      this._clientPairSess = null;
      if (sess.pairing) this.emit('pair:failed', { reason: '连接中断' });
    }
  }

  _cleanupPairing(sess, reason) {
    clearTimeout(sess.pairTimer);
    if (this.pendingPairB && this.pendingPairB.ws === sess.ws) this.pendingPairB = null;
    if (this._clientPairSess && this._clientPairSess.ws === sess.ws) this._clientPairSess = null;
    try { sess.ws.close(); } catch { /* ignore */ }
    this.emit('pair:failed', { reason });
  }

  _failPair(sess, reason) {
    clearTimeout(sess.pairTimer);
    this._disarmHandshakeTimer(sess);
    try { sendJson(sess.ws, { type: MsgType.PAIR_ABORT, reason: 'failed' }); } catch { /* ignore */ }
    try { sess.ws.close(); } catch { /* ignore */ }
    sess.pairing = null;
    if (this._clientPairSess && this._clientPairSess.ws === sess.ws) this._clientPairSess = null;
    this.emit('pair:failed', { reason });
  }

  _failPairB(reason) {
    const p = this.pendingPairB;
    if (p) {
      clearTimeout(p.ws._sess.pairTimer);
      try { sendJson(p.ws, { type: MsgType.PAIR_ABORT, reason: 'failed' }); } catch { /* ignore */ }
      try { p.ws.close(); } catch { /* ignore */ }
      this.pendingPairB = null;
    }
    this.emit('pair:failed', { reason });
  }

  _pairDoneB(sess, key) {
    clearTimeout(sess.pairTimer);
    this.store.addPeer(sess.pairing.peerId, sess.pairing.peerName, key);
    const info = { deviceId: sess.pairing.peerId, deviceName: sess.pairing.peerName };
    sess.pairing = null;
    this.pendingPairB = null;
    this._unauthCount = Math.max(0, this._unauthCount - 1);
    this.emit('pair:done', info);
    setTimeout(() => { try { sess.ws.close(); } catch { /* ignore */ } }, 500);
  }

  _pingAll() {
    const now = Date.now();
    const all = [];
    for (const wss of this.servers) {
      for (const ws of wss.clients) all.push(ws);
    }
    for (const ws of all) {
      const sess = ws._sess;
      if (!sess || !sess.authed) continue;
      if (now - (sess.lastPong || now) > PONG_TIMEOUT_MS) {
        try { ws.terminate(); } catch { /* ignore */ }
        continue;
      }
      try {
        this._sendInner(ws, InnerType.PING, {});
      } catch { /* ignore */ }
    }
  }
}

module.exports = { SignalingNode, DEFAULT_PORT };

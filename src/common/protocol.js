// LAN Call 信令协议 v2 —— 全平台共享契约（Windows / 鸿蒙必须一致实现）
// v2（2026-10-22）：配对改用 X25519 ECDH + SAS 双方比对（v1 的 6 位配对码+proof
//   可被离线穷举，已废弃）；会话密钥经 HKDF 双向派生；enc 帧带方向+序号 AAD。
// v1 仅为未发布原型，无兼容需求。

'use strict';

const PROTO_VERSION = 2;
const DEFAULT_PORT = 48217;

// 明文阶段消息类型（握手 / 配对 / 会话认证）
const MsgType = Object.freeze({
  HELLO: 'hello',               // { v, deviceId, deviceName }
  PAIR_REQUEST: 'pair-request', // A→B { deviceId, deviceName, ephPubA }
  PAIR_PUBKEY: 'pair-pubkey',   // B→A { deviceId, ephPubB }
  PAIR_CONFIRM: 'pair-confirm', // 双向 { mac }（SAS 比对通过后）
  PAIR_DONE: 'pair-done',
  PAIR_ABORT: 'pair-abort',     // { reason }
  AUTH_CHALLENGE: 'auth-challenge', // A→B { nonceA }
  AUTH_RESPONSE: 'auth-response',   // B→A { deviceId, nonceB, macB }
  AUTH_OK: 'auth-ok',               // A→B { macA }
  ENC: 'enc', // 加密帧 { dir, seq, iv, ct, tag }，见下
});

// 加密内层消息类型（认证完成后）
const InnerType = Object.freeze({
  CALL_REQUEST: 'call-request', // { sdp }
  CALL_ACCEPT: 'call-accept',   // { sdp }
  CALL_REJECT: 'call-reject',   // { reason }
  ICE: 'ice',                   // { candidate }
  HANGUP: 'hangup',
  PING: 'ping',
  PONG: 'pong',
});

const RejectReason = Object.freeze({
  BUSY: 'busy',
  DECLINED: 'declined',
  NO_MEDIA: 'no-media',
  TIMEOUT: 'timeout',
});

// ---- v2 密码学契约（鸿蒙 cryptoFramework 必须逐字实现） ----
// 配对：
//   S = X25519(ephPrivA, ephPubB) = X25519(ephPrivB, ephPubA)   (32B)
//   T = ephPubA ‖ ephPubB ‖ idA ‖ idB                            (transcript)
//   K_master = HKDF-SHA256(S, salt="lan-call-v2", info="master|idA|idB", 32)
//   SAS      = HMAC-SHA256(HKDF(S,"sas"), T)[0..4] BE uint32 mod 10^6（6 位）
//   macA     = HMAC-SHA256(K_master, "lan-call-pair-confirm-a" ‖ T)
//   macB     = HMAC-SHA256(K_master, "lan-call-pair-confirm-b" ‖ T)
// 会话（每次建连）：
//   macB = HMAC(K_master, "lan-call-auth-b" ‖ nonceA ‖ nonceB ‖ idA ‖ idB)
//   macA = HMAC(K_master, "lan-call-auth-a" ‖ nonceB ‖ nonceA ‖ idB ‖ idA)
//   Ks   = HKDF-SHA256(K_master, salt=nonceA‖nonceB, info="session", 64)
//   kAB  = Ks[0..32)  （A→B 方向）
//   kBA  = Ks[32..64)  （B→A 方向）
// 加密帧：AES-256-GCM，AAD = dir("a2b"/"b2a") ‖ seq(8B 大端)；
//   发送方 seq 从 0 严格递增；接收方校验 dir 与 seq，违例即断开。

function isValidIpv4(s) {
  if (typeof s !== 'string') return false;
  const parts = s.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

module.exports = {
  PROTO_VERSION,
  DEFAULT_PORT,
  MsgType,
  InnerType,
  RejectReason,
  isValidIpv4,
};

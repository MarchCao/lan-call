// LAN Call 密码学原语 v2 —— 平台无关
// 配对：X25519 ECDH + SAS（防离线穷举；配对码空间攻击不再适用）
// 会话：HKDF 双向密钥 + AES-256-GCM（AAD 绑定方向与序号，防重放/反射）
// 本模块只做纯函数运算，不触碰存储与传输。

'use strict';

const crypto = require('crypto');

// ---- 跨平台固定常量（鸿蒙移植必须逐字一致，见 protocol.js） ----
const HKDF_SALT = 'lan-call-v2';
const INFO_MASTER = 'master';
const INFO_SAS = 'sas';
const INFO_SESSION = 'session';

function randomBytes(n) {
  return crypto.randomBytes(n);
}

function hmacSha256(key, ...parts) {
  const h = crypto.createHmac('sha256', key);
  for (const p of parts) {
    h.update(Buffer.isBuffer(p) ? p : Buffer.from(String(p), 'utf8'));
  }
  return h.digest();
}

function safeEqual(a, b) {
  const ba = Buffer.isBuffer(a) ? a : Buffer.from(String(a), 'base64');
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(String(b), 'base64');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function hkdf(ikm, info, length) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, HKDF_SALT, info, length));
}

// ---- X25519 临时密钥对 ----
function generateEphemeralKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  // SPKI DER 固定 44 字节，末 32 字节为原始公钥
  const rawPub = publicKey.export({ type: 'spki', format: 'der' }).slice(-32);
  return { publicKey: rawPub, privateKey };
}

function publicKeyFromRaw(raw32) {
  const raw = Buffer.isBuffer(raw32) ? raw32 : Buffer.from(String(raw32), 'base64');
  if (raw.length !== 32) throw new Error('X25519 公钥长度非法');
  const spki = Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]);
  return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

function x25519SharedSecret(privateKey, peerRawPub) {
  return crypto.diffieHellman({ privateKey, publicKey: publicKeyFromRaw(peerRawPub) });
}

// ---- 配对密钥派生 ----
// transcript T = ephPubA ‖ ephPubB ‖ idA ‖ idB（字节拼接，id 为 UTF-8）
function buildTranscript(ephPubA, ephPubB, idA, idB) {
  return Buffer.concat([
    Buffer.isBuffer(ephPubA) ? ephPubA : Buffer.from(String(ephPubA), 'base64'),
    Buffer.isBuffer(ephPubB) ? ephPubB : Buffer.from(String(ephPubB), 'base64'),
    Buffer.from(String(idA), 'utf8'),
    Buffer.from(String(idB), 'utf8'),
  ]);
}

// 长期配对密钥（落盘）：K_master = HKDF(S, "master‖idA‖idB")
function deriveMasterKey(sharedSecret, idA, idB) {
  return hkdf(sharedSecret, `${INFO_MASTER}|${idA}|${idB}`, 32);
}

// SAS 校验码：双方屏幕显示 6 位数字，用户口头比对
function deriveSasCode(sharedSecret, transcript) {
  const kSas = hkdf(sharedSecret, INFO_SAS, 32);
  const mac = hmacSha256(kSas, transcript);
  const n = mac.readUInt32BE(0) % 1000000;
  return String(n).padStart(6, '0');
}

// 配对确认 MAC（SAS 比对通过后，双方各发一次，绑定 transcript 防 MITM）
function makePairConfirmMac(masterKey, role, transcript) {
  // role: 'a' | 'b'
  return hmacSha256(masterKey, `lan-call-pair-confirm-${role}`, transcript);
}

// ---- 会话认证 MAC（每次建连，防冒充） ----
function makeAuthMacB(key, nonceA, nonceB, idA, idB) {
  return hmacSha256(key, 'lan-call-auth-b', nonceA, nonceB, idA, idB);
}
function makeAuthMacA(key, nonceA, nonceB, idA, idB) {
  return hmacSha256(key, 'lan-call-auth-a', nonceB, nonceA, idB, idA);
}

// ---- 会话方向密钥 ----
// K_sess = HKDF(K_master, salt=nonceA‖nonceB, "session", 64)
// kAB = 前 32 字节（A→B），kBA = 后 32 字节（B→A）
function deriveSessionKeys(masterKey, nonceA, nonceB) {
  const nA = Buffer.isBuffer(nonceA) ? nonceA : Buffer.from(String(nonceA), 'base64');
  const nB = Buffer.isBuffer(nonceB) ? nonceB : Buffer.from(String(nonceB), 'base64');
  const okm = Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.concat([nA, nB]), INFO_SESSION, 64));
  return { kAB: okm.slice(0, 32), kBA: okm.slice(32, 64) };
}

// ---- 带方向/序号绑定的加密帧 ----
// AAD = dir("a2b"|"b2a") ‖ seq(8 字节大端)
// 接收方必须校验：dir 符合本端角色期望、seq 严格递增，否则丢弃并断开。
function seqToBytes(seq) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(seq));
  return b;
}

function encryptFrame(dirKey, dir, seq, plaintextObj) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.concat([Buffer.from(dir, 'utf8'), seqToBytes(seq)]);
  const cipher = crypto.createCipheriv('aes-256-gcm', dirKey, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(plaintextObj), 'utf8')), cipher.final()]);
  return {
    dir,
    seq,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

// 返回 { ok:true, plaintext } 或 { ok:false, reason }
// expectedDir: 本端期望收到的方向；expectedSeq: 期望的序号（严格递增）
function decryptFrame(dirKey, envelope, expectedDir, expectedSeq) {
  if (envelope.dir !== expectedDir) {
    return { ok: false, reason: `方向不符（收到 ${envelope.dir}，期望 ${expectedDir}，疑似反射攻击）` };
  }
  if (!Number.isInteger(envelope.seq) || envelope.seq !== expectedSeq) {
    return { ok: false, reason: `序号异常（收到 ${envelope.seq}，期望 ${expectedSeq}，疑似重放攻击）` };
  }
  try {
    const aad = Buffer.concat([Buffer.from(envelope.dir, 'utf8'), seqToBytes(envelope.seq)]);
    const decipher = crypto.createDecipheriv('aes-256-gcm', dirKey, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const pt = Buffer.concat([
      decipher.update(Buffer.from(envelope.ct, 'base64')),
      decipher.final(),
    ]);
    return { ok: true, plaintext: JSON.parse(pt.toString('utf8')) };
  } catch {
    return { ok: false, reason: '解密失败（密钥/完整性不匹配）' };
  }
}

module.exports = {
  HKDF_SALT,
  randomBytes,
  hmacSha256,
  safeEqual,
  hkdf,
  generateEphemeralKeypair,
  publicKeyFromRaw,
  x25519SharedSecret,
  buildTranscript,
  deriveMasterKey,
  deriveSasCode,
  makePairConfirmMac,
  makeAuthMacB,
  makeAuthMacA,
  deriveSessionKeys,
  encryptFrame,
  decryptFrame,
};

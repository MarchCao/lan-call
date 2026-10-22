# LAN Call 鸿蒙扩展接口设计（预留，阶段一不实现）

> 目标：未来增加鸿蒙客户端时，**复用核心协议、不重写信令协议**。
> 当前协议版本：**v2**（2026-10-22；v1 已废弃）。

## 1. 可直接复用的模块（JS/ArkTS 二选一）

| 模块 | 复用方式 |
|---|---|
| `src/common/protocol.js` | 协议常量与消息类型：逐字移植为 ArkTS（`protocol.ets`），字段名/取值保持一致 |
| `src/common/crypto.js` | v2 算法：X25519 / HKDF-SHA256 / HMAC-SHA256 / AES-256-GCM(AAD)，
用 `@ohos.security.cryptoFramework` 等价实现，**测试向量见 test/unit.test.js**，移植后必须跑通相同向量 |
| `src/core/pairing.js` | 状态机纯逻辑：移植为 ArkTS 类，输入/输出消息结构不变 |

## 2. 需按平台实现的适配层（`src/platform/harmonyos/`，新建）

```
src/platform/harmonyos/
  signaling.ets    # 实现与 main/signaling.js 相同的状态机驱动：
                   #  WebSocket 服务端+客户端（ohos.net.webSocket / socket）
                   #  hello → 配对(B)/认证 → AES-GCM 信道 → 内层消息
  media.ets        # 对接 WebRTC（ohos  WebRTC 封装或第三方库）：
                   #  实现与 renderer/media.js 相同的接口：
                   #  ensureLocalStream / makeOffer / handleOffer /
                   #  handleAnswer / addIceCandidate / setAudioMuted /
                   #  setVideoOff / close，回调 onIceCandidate/onRemoteStream/onIceState
  discovery.ets    # 实现 DiscoveryProvider 接口（mDNS：ohos.net.mdns）
  store.ets        # 配对密钥存储：Asset Store / Preferences 加密存储
```

## 3. 接口契约（鸿蒙实现必须满足，否则与 Windows 版不互通）

1. **线序协议**：WS 文本帧 JSON；`hello(v=2)` → 配对（ECDH+SAS）或认证 →
   `enc` 帧 `{dir,seq,iv,ct,tag}`；内层 `call-request/call-accept/call-reject/ice/hangup/ping/pong`。
2. **密码学一致性**（见 `protocol.js` §契约注释，逐字实现）：
   X25519 → `K_master=HKDF(S,"lan-call-v2","master|idA|idB")`；
   SAS = HMAC(HKDF(S,"sas"),T)[0..4] mod 10⁶；
   会话 `Ks=HKDF(K_master, nonceA‖nonceB, "session", 64)` 切分 kAB/kBA；
   AES-GCM AAD = dir‖seq(8B大端），seq 从 0 严格递增。以 unit.test.js 向量为准。
3. **SDP 互操作**：Offer/Answer 为标准 SDP；ICE 只用 host 候选（双方都不配 STUN）。
4. **端口**：默认 48217；应用包名建议 `top.haice.lancall`。
5. **设备发现**：阶段二 mDNS 服务类型定为 `_lancall._tcp.local.`，TXT 记录含 `deviceId`、`proto=2`。

## 4. 不建议复用的部分

- Electron 主进程/渲染进程划分（鸿蒙用 Ability + ArkUI 重写 UI）。
- `device-store.js` 的 safeStorage（改用鸿蒙密钥资产服务）。
- NSIS 打包（改用鸿蒙 App Pack）。

## 5. 互通验收（鸿蒙版完成时）

- Windows 发起 ↔ 鸿蒙接听，双向音视频正常。
- Windows 配对过的鸿蒙设备，鸿蒙重装后需重新配对（密钥不跨设备迁移）。
- 抓包抽查：配对完成后所有信令为 `enc` 信封，无明文 SDP。

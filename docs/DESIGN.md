# LAN Call｜局域网一对一视频通话 — 技术设计 v1.2

> 对应任务书《LAN Call｜局域网一对一视频通话开发任务 v1.1》。
> 本轮只实现 Windows ↔ Windows（阶段一：手动输入 IP 的双向音视频通话）。
> 鸿蒙只做架构预留，不实现。
>
> **v1.2 修订（2026-10-22，外部评审后）**：
> 配对协议由 v1（6 位配对码 + proof）升级为 **v2（X25519 ECDH + SAS 双方比对）**，
> 修复"配对码可被离线穷举"缺陷；会话密钥改为 HKDF 双向派生，enc 帧加方向+序号 AAD
> （防重放/反射）；收敛局域网暴露面。v1 仅为未发布原型，无兼容需求，已废弃。

## 1. 总体架构：四层 + 平台适配层

```
┌─────────────────────────────────────────────────┐
│ UI 层 (renderer/)        界面：本机信息/拨号/来电/通话中   │  Electron 实现 (阶段一)
├─────────────────────────────────────────────────┤
│ 信令层 (main/)           WebSocket 信令服务端+客户端        │  平台相关 (Node/Electron)
│   ├─ 配对/认证状态机 (core/pairing.js)  ← 可复用纯逻辑    │
│   └─ 消息加解密 (common/crypto.js)      ← 可复用纯逻辑    │
├─────────────────────────────────────────────────┤
│ 媒体层 (renderer/media.js)  WebRTC 音视频                │  阶段一: Chromium WebRTC
│                                                  │  鸿蒙: 对接 HarmonyOS WebRTC/AVSession
├─────────────────────────────────────────────────┤
│ 设备发现层 (discovery/)   阶段一: 手动 IP (NoopDiscovery) │  阶段二: mDNS 实现
│                          阶段二: mDNS 自动发现            │
├─────────────────────────────────────────────────┤
│ 协议契约 (common/protocol.js)  消息格式/端口/版本        │  全平台共享，不可分叉
└─────────────────────────────────────────────────┘
        平台适配层 (platform/): electron/ (阶段一) ｜ harmonyos/ (预留)
```

**模块化铁律**：`common/`（协议、密码学原语）与 `core/`（配对状态机纯逻辑）不依赖任何平台 API，
鸿蒙端可直接复用；`platform/` 下各平台只实现传输与媒体适配。

## 2. 网络模型：对等节点，无中心服务器

- 每个节点同时运行 **WebSocket 信令服务端**（默认端口 `48217`，可配）与客户端能力。
- 发起方作为 WS 客户端连向被叫方的 `ws://<对端IP>:48217`；一条 WS 连接承载一次配对或一次通话的全部信令。
- 任意一方都可发起，角色完全对称。
- **监听地址**：只绑定局域网 IPv4 接口（RFC1918 `10/8`、`172.16/12`、`192.168/16` 及链路本地
  `169.254/16`），跳过回环与公网地址；不做 UPnP/NAT-PMP 端口映射，不开放公网监听。
- ICE：`iceServers: []`，不配 STUN/TURN，只用 host 候选（同一子网足够）。

## 3. 信令协议 v2（`common/protocol.js`，全平台共享）

传输：WebSocket，JSON 文本帧。`maxPayload` 限制 256KB（SDP/ICE 帧远小于此值）。

### 3.1 明文阶段（仅握手、配对、会话认证；不含 SDP/媒体信息）

| type | 方向 | 字段 | 说明 |
|---|---|---|---|
| `hello` | 双向 | `deviceId, deviceName, proto` | 版本协商，`proto` 必须为 2 |
| `pair-request` | A→B | `deviceId, deviceName, ephPubA` | A 发起配对，携带 X25519 临时公钥 |
| `pair-pubkey` | B→A | `deviceId, ephPubB` | B 接受后回临时公钥，双方各自算出 SAS |
| `pair-confirm` | 双向 | `mac` | 本端用户确认 SAS 一致后发送的密钥确认 |
| `pair-done` | 双向 | — | 配对完成回执 |
| `pair-abort` | 双向 | `reason` | 任一方取消（SAS 不一致/拒绝/超时/限流） |
| `auth-challenge` | A→B | `nonceA` | 已配对设备的会话认证开始 |
| `auth-response` | B→A | `deviceId, nonceB, macB` | B 的应答证明 |
| `auth-ok` | A→B | `macA` | A 的应答证明，认证完成 |

> 注：A = 连接发起方（WS 客户端）。被动监听者无法窥探出任何长期密钥材料：
> 明文只含临时公钥。

加密内层消息类型（认证完成后，均为 enc 帧）：

| type | 说明 |
|---|---|
| `call-request` | `{ sdp }` 发起通话（携带 Offer） |
| `call-accept` | `{ sdp }` 接听（携带 Answer） |
| `call-reject` | `{ reason }` 拒接 |
| `ice` | `{ candidate }` ICE 候选（trickle） |
| `hangup` | 任一方挂断，对端立即结束并提示 |
| `ping`/`pong` | 保活（30s） |

### 3.2 配对数学 v2（`core/pairing.js` + `common/crypto.js`）

- 双方各生成 **X25519 临时密钥对**（一次配对用一次，用后擦除）。
- `S = X25519(ephPrivA, ephPubB) = X25519(ephPrivB, ephPubA)`（32 字节）。
- `T = ephPubA ‖ ephPubB ‖ idA ‖ idB`（transcript）。
- 长期配对密钥 `K_master = HKDF-SHA256(S, salt="lan-call-v2", info="master|idA|idB", 32)`，
  safeStorage 加密落盘，按 `deviceId` 索引。
- **SAS 校验码** = `HMAC-SHA256(HKDF(S,"sas"), T)` 前 4 字节 BE uint32 mod 10⁶，
  双方屏幕各显示 6 位数字，用户当面/电话比对一致后各自点"确认"。
- 确认消息 `macA = HMAC(K_master, "lan-call-pair-confirm-a" ‖ T)`（B 同理），
  双方互相验证——**双方确认**绑定在 transcript 上。
- **为什么 v1 被废弃**：v1 的 saltA/saltB/proofB 明文传输，攻击者抓包后可对
  10⁶ 配对码空间离线穷举（单次 PBKDF2(100k) 约 14ms，CPU 约 3.9 核·小时，
  GPU 分钟级），且 K 即长期密钥，一次抓包永久破解。v2 明文只有临时公钥，
  被动攻击者无法离线求解 S；主动中间人会因 SAS 不一致被用户发现，
  即使用户误点确认，`pair-confirm` MAC 验证也会失败。

### 3.3 会话密钥与加密帧（防重放/反射）

- 会话认证沿用 nonce 双向 HMAC（密钥为 `K_master`）。
- 认证完成后：`Ks = HKDF-SHA256(K_master, salt=nonceA‖nonceB, info="session", 64)`，
  `kAB = Ks[0..32)`（A→B），`kBA = Ks[32..64)`（B→A）。**每连接、每方向独立密钥**。
- 加密帧 `{ type:'enc', dir, seq, iv, ct, tag }`，AES-256-GCM，
  **AAD = dir("a2b"/"b2a") ‖ seq(8 字节大端）**。
- 发送方 `seq` 从 0 严格递增；接收方校验：`dir` 必须符合本端角色期望
  （防反射），`seq` 必须等于期望值（防重放/乱序），违例立即断开并上报告警。
- WS 自身保证同连接有序，故采用严格递增（不设滑动窗口）。

### 3.4 暴露面收敛（局域网不视为可信）

- 未认证入站连接上限 16，超限直接关闭。
- `pair-request` 按源 IP 限流：每分钟 ≤5 次；`pair-confirm` 验证失败 ≥3 次
  则该 IP 冷却 60 秒。
- 握手总超时 20 秒（hello 10 秒）；配对总超时 120 秒。
- `maxPayload` 256KB；JSON 解析失败直接丢弃不回包。

## 4. 媒体层（`renderer/media.js`）

- `RTCPeerConnection({ iceServers: [] })`，`getUserMedia({video:true, audio:true})`。
- 本地预览 + 远端 `ontrack` 渲染；支持静音/关视频（仅停发 track，不重建连接）。
- 阶段一异常：`NotFoundError`（无摄像头/麦克风）→ 明确中文提示；
  `NotAllowedError` → 提示检查系统隐私设置。
- 断线：`iceConnectionState` → `disconnected/failed` 时 UI 提示（自动重连进阶段三）。

## 5. Electron 安全

- `nodeIntegration:false`、`contextIsolation:true`、`sandbox:true`；
  渲染进程只经 `preload` 的 `contextBridge` 调用白名单 IPC（`window.lanCall`）。
- **密钥边界（v1.2 澄清）**：长期配对密钥 `K_master`、会话密钥、临时私钥
  只存在主进程，永不进渲染进程。**SAS 校验码是例外**：它必须显示在屏幕上
  供用户比对，因此经 IPC 到达渲染进程显示，用后即清。SAS 是 20bit 的
  一次性 MITM 检测值，不知道它无法推导任何密钥；拿到渲染进程内存
  的攻击者已等同于控制本机，边界仍在长期密钥上。
- CSP：`default-src 'self'`；无远程脚本、无统计、无自动更新（阶段一不做，避免外部依赖）。
- 不关闭证书校验（本机全明文 WS + 消息级加密，不依赖 TLS；未来如需 WSS 必须走系统证书）。
- 防火墙：不自动改规则；首次监听由 Windows 系统弹窗请用户放行，UI 内给出中文指引。

## 5.1 Windows 实战注意（评审补充）

- **多网卡**：Hyper-V/WSL/VPN 虚拟网卡会导致"本机 IP"出现多个。UI 列出全部
  局域网 IP 并标注网卡名；呼叫方应使用对端真实局域网 IP（非虚拟网卡）。
  后续可在设置中允许隐藏虚拟网卡。
- **Wi-Fi 客户端隔离**：部分路由器/企业 Wi-Fi 默认隔离无线客户端，两台机器
  将无法互连。排障指引：关闭 AP 隔离，或改用有线/手机热点组网。
- **标准用户防火墙**：放行弹窗需要管理员权限；标准用户首次运行需管理员协助
  放行一次，之后不再打扰。UI 检测到监听失败时给出明确指引。
- **网卡切换**：休眠唤醒/插拔网线/切换 Wi-Fi 后监听地址可能失效。阶段一要求
  用户重启软件；阶段三加入网络变化监听自动重绑。
- **ICE 候选**：PeerConnection 必须在 `getUserMedia` 授权**之后**创建，
  否则可能只拿到 `.local` 候选。`media.js` 已保证该顺序（先 `ensureLocalStream`）。

## 6. 阶段划分与本轮范围

- **阶段一（本轮）**：手动 IP、配对（ECDH+SAS 双方确认）、双向音视频、挂断通知、异常提示。
  交付：源码 + 技术设计（本文件）+ 最小原型 + 本机可测项的测试记录。
  **安装包状态：已构建、未验证**——Linux 交叉构建 + 解包验证，未在 Windows 上运行过；
  无代码签名，Windows SmartScreen 会拦截；按任务书安装包属阶段四交付物。
- **阶段二**：mDNS 自动发现（`discovery/mdns.js` 实现 `DiscoveryProvider` 接口）、来电流程细化。
- **阶段三**：摄像头/麦克风选择、断线重连、网卡切换自动重绑。
- **阶段四**：NSIS 安装包真机验证、真实断网双机测试（需两台 Windows 真机，见 `docs/TESTING.md`）。

## 7. 未在本机验证的事项（诚实声明）

- 两台真实 Windows 之间的通话（本机为 Linux，无 Windows 设备）。
- 真实摄像头/麦克风（本机无音视频设备，用 Chromium fake device 测试信令+建连流程）。
- RTP 音视频帧传输：本机 VM 沙箱在 syscall 层禁用 UDP 发送（`send EPERM`；
  已验证 fresh network namespace 同样 EPERM，排除网络配置因素），ICE 物理上无法建连。
  e2e 按 UDP 探测自动跳过媒体断言，真机自动执行。
- 30 分钟连续通话、Windows 防火墙弹窗体验、NSIS 安装包在 Windows 上的安装运行、
  SmartScreen 拦截处理。
- 上述列入 `docs/TESTING.md` 的"待真机验证"清单，不宣称已达标。

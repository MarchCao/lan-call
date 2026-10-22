# LAN Call 阶段一测试记录

> 原则：未经测试不宣称达标。以下分"已验证"与"未验证（待真机）"两部分。

## 1. 已验证（2026-10-22，本机 Linux VM）

### 1.1 单元测试 `npm run test:unit` — 17/17 通过（v2）
- 协议：版本号 2、IPv4 校验
- 密码学 v2：X25519 共享密钥一致；非法公钥拒绝；SAS 双方一致、MITM 替换公钥则 SAS 不一致；
  长期配对密钥一致；pair-confirm MAC 双向验证且 a/b 不可互换
- 会话密钥与 enc 帧防护：双向密钥派生一致且隔离；加解密往返；**重放攻击被拒；
  反射攻击被拒；序号跳跃被拒；篡改密文失败**
- 配对状态机 v2：完整 ECDH+SAS 双方确认；对方先确认的 deferred 路径；
  SAS 不一致取消；MITM 下 confirm MAC 失败
- 会话认证：完整双向认证；密钥不匹配失败；nonce 重放失败

### 1.2 信令集成测试 `npm run test:signaling` — 全部通过（v2）
双 `SignalingNode` 经回环（不同端口）验证：
- 未配对设备发起通话被拒
- ECDH+SAS 配对：双方 SAS 一致→各自确认→`pair:done`，长期密钥一致落盘
- SAS 不一致时双方取消
- 通话：Offer/Answer 经**方向+序号保护的加密帧**送达；ICE 透传；A 挂断 B 立即收到通知

### 1.3 端到端测试 `xvfb-run -a npm run test:e2e` — 通过（含环境限制说明）
双 Electron 真实实例 + 真实 UI 操作（Playwright CDP 驱动）+ Chromium fake 音视频设备：
- A 生成配对码 → B 接受并输入 → 双方 toast"配对成功"
- A 呼叫 → B 来电弹窗 → B 接听 → 双方状态"通话中"
  （Offer/Answer SDP 经 AES-GCM 加密信令完成交换——应用协议栈全链路打通）
- A 挂断 → B 状态"通话已结束"
- **未验证项**：RTP 音视频帧传输。本机 VM 沙箱在 syscall 层禁用 UDP 发送
  （`send EPERM`；已用 fresh network namespace 复测，同样 EPERM，排除网络配置因素），
  ICE 候选（UDP/TCP host）无法建连，`remoteVideo.videoWidth` 断言按设计跳过；
  测试先探测 UDP 可用性，真机（UDP 正常）上会自动执行完整视频帧断言。

### 1.4 构建验证
- `npm run dist:win` 的 electron-builder 流程在 Linux 需 wine（抽取卸载程序步骤），
  本环境无 sudo 不可用；改用缓存内原生 `makensis` + 手写 `installer.nsi`
  产出 NSIS 安装包，并经 7zip 解包验证（含 `LAN Call.exe`、完整运行时、`Uninstall.exe`）。
- **安装包状态：已构建、未验证**——未在 Windows 上运行；无代码签名，
  SmartScreen 会拦截；按任务书属阶段四交付物。

## 2. 未验证 — 待两台 Windows 真机（阶段四）

| # | 验收标准 | 待验证内容 |
|---|---|---|
| 1 | 两台电脑分别安装相同程序 | NSIS 包在 Win10/Win11 x64 安装运行 |
| 2 | 任意一方可发起 | A→B 与 B→A 双向发起 |
| 3 | 双向声音视频正常 | 真实摄像头/麦克风/扬声器 |
| 4 | 断网后从零建连 | 拔掉外网（保留局域网）配对+通话 |
| 5 | 连续 30 分钟 | 长时间通话稳定性 |
| 6 | 挂断即时通知 | 真机网络下挂断延迟 |
| 7 | 异常提示 | 无摄像头/无麦克风/防火墙拦截/对端忙 |
| 8 | 独立运行 | 不装 Node.js/无手动服务 |

真机测试清单模板见 `docs/TESTING.md` 附录（阶段四执行时填写）。

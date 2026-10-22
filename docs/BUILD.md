# LAN Call 构建与安装说明（阶段一）

## 环境要求（构建机）

- Node.js ≥ 20，npm ≥ 10
- Windows 安装包可在 Linux/macOS/Windows 上交叉构建（electron-builder 内置 NSIS）

## 构建步骤

```bash
cd lan-call
npm install            # 安装依赖（含 Electron 二进制）
npm run dist:win       # 生成 Windows x64 安装包 → dist/LAN-Call-Setup-0.1.0-win-x64.exe
```

## 安装（Windows 10/11 64 位）

1. 在两台电脑上分别运行安装包，按向导完成安装（无需管理员权限，默认装到当前用户目录）。
2. 首次启动：Windows 防火墙弹窗 → 勾选"专用网络"→ 允许访问。
   （软件不会自动修改防火墙规则，必须由用户手动确认。）
3. 不需要安装 Node.js，不需要手动启动任何服务器。

## 使用流程（阶段一）

1. 两台电脑打开软件，记下各自的"本机 IP"。
2. A 在"设备配对"输入 B 的 IP → 发起配对 → A 屏幕显示 6 位配对码。
3. B 看到配对请求 → 接受 → 输入 A 显示的 6 位码 → 确认。
4. 任一方在"视频通话"输入对方 IP → 发起通话；对方接听即建立双向音视频。
5. 挂断：任一方点"挂断"，对方立即收到结束通知。

## 目录结构

```
src/
  common/      protocol.js（跨平台协议契约） crypto.js（密码学原语）
  core/        pairing.js（配对/认证状态机，纯逻辑）
  main/        main.js signaling.js device-store.js netutil.js（主进程）
  preload/     preload.js（安全 IPC 桥）
  renderer/    index.html styles.css app.js media.js（界面 + WebRTC）
  discovery/   index.js（阶段一：手动 IP 存根；阶段二：mDNS）
test/          unit.test.js / signaling.test.js / e2e-call.test.js
docs/          DESIGN.md BUILD.md TESTING.md KNOWN_ISSUES.md HARMONYOS_EXTENSION.md
```

## 测试命令

```bash
npm run test:unit        # 纯逻辑单元测试（无网络）
npm run test:signaling   # 双节点信令集成测试（回环）
xvfb-run -a npm run test:e2e  # 双 Electron 实例端到端（需 Linux 图形栈；Windows 下直接运行）
```

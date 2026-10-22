# LAN Call｜局域网一对一视频通话

完全离线的局域网视频通话软件。阶段一：Windows ↔ Windows（手动输入 IP）。

## 特性（阶段一 v0.1.0）

- ✅ 两台 Windows 电脑安装相同软件，任意一方可发起/接听
- ✅ 无服务器、无公网、无账号、无广告、无统计
- ✅ 局域网自动发现失败时手动输入 IP（自动发现为阶段二）
- ✅ 首次配对双方确认（6 位配对码 + 双向 proof）；之后每次建连双向认证
- ✅ 信令全程 AES-256-GCM 加密；媒体 WebRTC DTLS-SRTP 标准加密
- ✅ 只绑定局域网网卡；不修改防火墙（由用户在系统弹窗中手动放行）
- ✅ Electron 进程隔离：`sandbox` + `contextIsolation`，密钥不出主进程
- ✅ 音视频不上传、不保存

## 文档

- `docs/DESIGN.md` — 技术设计（四层架构、协议、安全）
- `docs/BUILD.md` — 构建与安装说明
- `docs/TESTING.md` — 测试记录（含未验证项诚实声明）
- `docs/KNOWN_ISSUES.md` — 已知缺陷与限制
- `docs/HARMONYOS_EXTENSION.md` — 鸿蒙扩展接口设计

## 快速开始

```bash
npm install
npm start                  # 开发运行
npm run test:unit          # 单元测试
npm run test:signaling     # 信令集成测试
xvfb-run -a npm run test:e2e  # 端到端测试（Linux）
```

Windows 安装包：`npm run dist:win`（Linux 下需原生 makensis，见 `installer.nsi`
构建说明；electron-builder 的 wine 步骤在本环境不可用，已改用原生 NSIS 链）。

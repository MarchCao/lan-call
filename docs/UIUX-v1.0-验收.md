# LAN Call 官网优化 UI/UX v1.0 —— 验收包

日期：2026-10-22　分支：`uiux-v1`（**未部署到线上，未经批准不合并/不发布**）
预览：本地构建 `~/workspace/lan-call/site/`（分支 uiux-v1），三宽度截图见 `~/workspace/uiux-preview/`

## 一、修改文件清单

| 文件 | 变更 |
|---|---|
| `site/index.html` | 全量重写（见下） |
| `site/shots/shot-main.png` | 新增：真实主界面截图（测试环境，xvfb 抓取后裁切） |
| `site/shots/shot-pairing.png` | 新增：真实配对确认截图（同上） |
| `site/shots/shot-call.png` | 新增：真实视频通话截图（同上，Chromium 虚拟视频图案） |

未动：下载地址、安装包、SHA256、通信协议、客户端程序、其余 4 个页面、robots/sitemap/CNAME/百度验证文件。

## 二、首页变更要点（对照任务书）

1. **结构**：导航 → 首屏（H1/副标题/双按钮/版本信息）→ 真实截图 → 三步指南 → 核心特点 → 安全与隐私 → 下载与校验 → FAQ → 页脚。旧版单列卡片堆叠、大面积留白已消除。
2. **首屏文案**：采用任务书指定文案（主标题/副标题/按钮/版本信息 v0.2.4 · Windows 10/11 · 64 位 · 136 MB）。
3. **视觉**：蓝色主色（#1a66cc）+ 白/浅灰，最大宽度 1120px，桌面双栏，iPad/手机单列响应式；无 UI 框架；`:focus-visible` 焦点环；中文。
4. **导航**：主导航 下载/使用指南/安全与隐私（锚点）；技术支持/离线安全/物理隔离部署/关于 进页脚次级导航。
5. **SmartScreen 文案**：旧版"点击'更多信息'→'仍要运行'即可"（鼓励绕过）已改为中性表述——说明无代码签名是系统正常防护，先核对 SHA256 再自行决定。
6. **新增**：PowerShell 校验命令、"下载需联网/运行可离线"区分、测试版已知限制清单、FAQ（4 条，源自真实踩坑）。
7. **截图诚实性**：三张均为 v0.2.4 真实程序在 xvfb 下渲染抓取（配对→通话全流程真实走通），非 AI 生成；caption 注明测试环境与虚拟设备。

## 三、链接检查（本地 200 全过）

index.html / offline-security.html / air-gapped-solution.html / support.html / about.html /
robots.txt / sitemap.xml / shots/×3 / baidu_verify_codeva-ahqqnPnHTK.html / CNAME —— 全部 200。
锚点：#download #guide #security #faq #shots 全部存在有效。

## 四、声明证据核查记录

| 页面声明 | 证据 |
|---|---|
| X25519 ECDH 临时密钥协商 | `src/common/crypto.js`、`src/core/pairing.js`（v2 协议）；单元测试 17/17 |
| 6 位 SAS 校验码双方比对 | `crypto.js:78` (`% 1000000`)；e2e 测试双方 SAS 一致断言通过 |
| 每次通话派生独立会话密钥 | `src/common/protocol.js`（kAB/kBA，HKDF） |
| AES-256-GCM 加密 | `src/common/protocol.js`（AES-256-GCM 明文引用） |
| 防重放/防反射（序号递增进 AAD、方向校验） | `src/common/protocol.js`（seq 相关 3 处） |
| 暴露面：未认证连接上限 16、握手 20s 超时、配对 5 次/分钟/IP、确认失败 3 次冷却 60s、消息体 256KB | `src/main/signaling.js`（MAX_UNAUTH_CONNECTIONS=16、HANDSHAKE_TIMEOUT_MS=20000、PAIR_REQ_PER_MIN_PER_IP=5、COOLDOWN_MS=60000、maxPayload 256KB） |
| 长期密钥永不进入渲染进程 | main 进程 12 处 `ipcMain.handle`，`preload.js` contextBridge 隔离 |
| 信令只监听局域网网卡地址 | `src/main/signaling.js` `start()` 绑定 `listLanIpv4()`（loopback 仅测试 env 开关） |
| 不依赖公网 STUN/TURN | `src/renderer/media.js` 无 stun/turn 配置 |
| 无账号、无统计、不上传不保存音视频 | 代码 grep：无统计/上报/广告模块；用户真机测试确认 |
| 配对密钥只保存在本机 | `src/main/device-store.js` |
| v0.2.4 · 136 MB · SHA256 | Release 文件 136,341,371 字节；SHA256 `1c592620…dfeada` 与页面公布值一致 |
| "通话已在单机双开与真机环境验证；两台独立电脑/断网建连/长时间通话仍在测试中" | 用户 2026-10-22 真机双开测试记录；其余三项确未验证（诚实标注） |
| 物理隔离相关 | 措辞为"适用于…的技术方案"，页内注明"部署前请结合本单位安全管理制度自行评估"；**未宣称**已在物理隔离环境验证 |

## 五、优化前后对比

- 旧版：`~/workspace/uiux-preview/page-before.png`（单列居中、无截图、SmartScreen 鼓励绕过、无 PowerShell、无 FAQ）
- 新版桌面：`~/workspace/uiux-preview/page-desktop.png`
- 新版 iPad(768)：`~/workspace/uiux-preview/page-ipad.png`
- 新版手机(390)：`~/workspace/uiux-preview/page-mobile.png`（顶部导航小屏自动隐藏，页脚保留全部链接）

## 六、未完成事项

1. **未部署**：分支 `uiux-v1` 未合并到 main，未推送 gh-pages。待你验收通过后明确指令再发布。
2. Google Search Console、Bing Webmaster Tools 尚未提交（百度已完成：验证通过 + 5 URL 推送成功）。
3. 小红书招募测试进展未知（你自行操作）。
4. 配对截图右下角有一小块系统 toast 残影（真实程序元素，非伪造；如介意可重裁）。
5. 阶段二/三（自动发现、设备选择下拉、断线重连）未开始；阶段四两台真机验收未做。

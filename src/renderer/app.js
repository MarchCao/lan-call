// LAN Call 渲染进程 UI 逻辑
// 经 window.lanCall（preload 白名单）与主进程通信；不接触密钥。

'use strict';

const $ = (id) => document.getElementById(id);

const media = new window.MediaSession();
let callState = 'idle'; // idle | dialing | ringing | active
let muted = false;
let videoOff = false;

function toast(msg, ms = 3500) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), ms);
}

function setStatus(text, cls = '') {
  const s = $('callStatus');
  s.textContent = text;
  s.className = `status ${cls}`;
}

async function invoke(name, ...args) {
  const r = await window.lanCall[name](...args);
  if (!r.ok) throw new Error(r.error);
  return r.data;
}

// ---------- 初始化 ----------
async function init() {
  try {
    const info = await invoke('getInfo');
    $('deviceName').value = info.deviceName || '';
    $('portInfo').textContent = String(info.port);
    $('ipList').innerHTML = info.ips.length
      ? info.ips.map((i) => `<code>${i.address}</code>`).join('')
      : '<span class="hint">未检测到局域网 IP（请检查网络连接）</span>';
    renderPeers(info.pairedDevices || []);
    if (info.storeMode === 'memory') {
      $('storeWarn').classList.remove('hidden');
    }
    const ns = $('netStatus');
    ns.textContent = info.ips.length ? '● 服务运行中' : '● 服务异常：无局域网 IP';
    ns.className = `net-status ${info.ips.length ? 'ok' : 'err'}`;
  } catch (e) {
    toast(`初始化失败：${e.message}`);
  }

  window.lanCall.onEvent((name, p) => handleEvent(name, p || {}));
  bindButtons();
}

function renderPeers(peers) {
  const box = $('peerList');
  if (!peers.length) {
    box.innerHTML = '<p class="hint">暂无</p>';
    return;
  }
  box.innerHTML = '';
  for (const p of peers) {
    const div = document.createElement('div');
    div.className = 'peer';
    const name = document.createElement('span');
    name.textContent = `${p.deviceName}（配对于 ${p.pairedAt.slice(0, 10)}）`;
    const btn = document.createElement('button');
    btn.className = 'btn small';
    btn.textContent = '忘记';
    btn.onclick = async () => {
      if (!confirm(`确定删除与「${p.deviceName}」的配对吗？之后需重新配对才能通话。`)) return;
      try {
        await invoke('forgetPeer', p.deviceId);
        toast('已删除配对');
        const info = await invoke('getInfo');
        renderPeers(info.pairedDevices || []);
      } catch (e) { toast(e.message); }
    };
    div.append(name, btn);
    box.appendChild(div);
  }
}

// ---------- 按钮 ----------
function bindButtons() {
  $('saveName').onclick = async () => {
    try {
      await invoke('setDeviceName', $('deviceName').value.trim());
      toast('设备名称已保存');
    } catch (e) { toast(e.message); }
  };

  // 解析 "IP" 或 "IP:端口"（单机双实例时用 127.0.0.1:48218）
  function parseIpPort(s) {
    const m = s.match(/^(.*?):(\d{1,5})$/);
    if (m) {
      const p = parseInt(m[2], 10);
      if (p > 0 && p < 65536 && m[1]) return { ip: m[1], port: p };
    }
    // window.__testPeerPort 仅 e2e 测试使用（同机双实例），生产环境为 undefined
    return { ip: s, port: window.__testPeerPort };
  }

  // ---- 麦克风电平条 ----
  let micMeterRAF = 0, micMeterCtx = null;
  function startMicMeter() {
    stopMicMeter();
    try {
      const stream = media.localStream;
      if (!stream || !stream.getAudioTracks().length) return;
      micMeterCtx = new (window.AudioContext || window.webkitAudioContext)();
      const src = micMeterCtx.createMediaStreamSource(stream);
      const analyser = micMeterCtx.createAnalyser();
      analyser.fftSize = 512;
      src.connect(analyser);
      const data = new Uint8Array(analyser.frequencyBinCount);
      const bar = $('micLevel');
      const tick = () => {
        analyser.getByteFrequencyData(data);
        let sum = 0;
        for (let i = 0; i < data.length; i++) sum += data[i];
        const lvl = Math.min(100, Math.round(sum / data.length / 2.55 * 4));
        if (bar) bar.style.width = lvl + '%';
        micMeterRAF = requestAnimationFrame(tick);
      };
      tick();
    } catch { stopMicMeter(); }
  }
  function stopMicMeter() {
    if (micMeterRAF) { cancelAnimationFrame(micMeterRAF); micMeterRAF = 0; }
    if (micMeterCtx) { micMeterCtx.close().catch(() => {}); micMeterCtx = null; }
    const bar = $('micLevel');
    if (bar) bar.style.width = '0%';
  }

  // ---- 音视频设备列表 ----
  async function refreshDevices() {
    try {
      const devs = await navigator.mediaDevices.enumerateDevices();
      const inUseAudio = media.localStream ? (media.localStream.getAudioTracks()[0] || {}).label || '' : '';
      const inUseVideo = media.localStream ? (media.localStream.getVideoTracks()[0] || {}).label || '' : '';
      const row = (kind, inUse) => {
        const list = devs.filter(d => d.kind === kind);
        if (!list.length) return '无';
        return list.map(d => {
          const label = d.label || '(未命名：需先允许麦克风/摄像头权限)';
          const mark = inUse && d.label && d.label === inUse ? ' <b>← 使用中</b>' : '';
          return label + mark;
        }).join('<br>');
      };
      $('devVideo').innerHTML = row('videoinput', inUseVideo);
      $('devAudio').innerHTML = row('audioinput', inUseAudio);
      $('devSpeaker').innerHTML = row('audiooutput', '');
    } catch { /* 忽略 */ }
  }
  $('devRefresh').onclick = () => { refreshDevices(); toast('设备列表已刷新'); };
  $('devBeep').onclick = () => {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.connect(g); g.connect(ctx.destination);
      o.frequency.value = 880; g.gain.value = 0.3;
      o.start(); o.stop(ctx.currentTime + 0.4);
      o.onended = () => ctx.close();
      toast('已播放测试音，能听到说明扬声器正常');
    } catch (e) { toast(`无法播放测试音：${e.message}`); }
  };
  if (navigator.mediaDevices) {
    navigator.mediaDevices.addEventListener('devicechange', refreshDevices);
    refreshDevices();
  }

  $('pairBtn').onclick = async () => {
    const { ip, port } = parseIpPort($('pairIp').value.trim());
    if (!ip) return toast('请先输入对方 IP');
    try {
      setStatus('正在发起配对…');
      await invoke('pair', ip, port);
    } catch (e) { toast(`配对失败：${e.message}`); setStatus('空闲'); }
  };

  $('pairAcceptBtn').onclick = async () => {
    try {
      await invoke('pairAccept');
      $('pairAcceptBtn').disabled = true;
      $('pairRejectBtn').disabled = true;
      setStatus('已接受，正在生成校验码…');
    } catch (e) { toast(e.message); }
  };
  $('pairRejectBtn').onclick = async () => {
    try { await invoke('pairReject'); } catch (e) { toast(e.message); }
    hidePairIncoming();
  };
  $('sasOkBtn').onclick = async () => {
    try {
      await invoke('pairSasConfirm', true);
      setStatus('已确认，等待对方确认…');
      $('sasOkBtn').disabled = true;
      $('sasNoBtn').disabled = true;
    } catch (e) { toast(e.message); }
  };
  $('sasNoBtn').onclick = async () => {
    try { await invoke('pairSasConfirm', false); } catch (e) { toast(e.message); }
  };

  $('callBtn').onclick = async () => {
    const raw = $('callIp').value.trim();
    const { ip, port } = parseIpPort(raw);
    if (!ip) return toast('请先输入对方 IP');
    if (callState !== 'idle') return toast('当前有通话正在进行');
    try {
      setStatus('正在打开摄像头/麦克风…');
      const local = await media.ensureLocalStream();
      $('localVideo').srcObject = local;
      refreshDevices();
      startMicMeter();
      setStatus(`正在呼叫 ${raw}…`);
      callState = 'dialing';
      $('callControls').classList.remove('hidden');
      const offerSdp = await media.makeOffer();
      if (!media.videoAvailable) toast('摄像头不可用，已切换为纯音频通话', 4000);
      await invoke('call', ip, offerSdp, port);
      wireMediaCallbacks();
    } catch (e) {
      endUiCall();
      setStatus(`呼叫失败：${e.message}`, 'err');
      toast(e.message, 5000);
    }
  };

  $('answerBtn').onclick = async () => {
    try {
      setStatus('正在打开摄像头/麦克风…');
      const local = await media.ensureLocalStream();
      $('localVideo').srcObject = local;
      refreshDevices();
      startMicMeter();
      if (!media.videoAvailable) toast('摄像头不可用，已切换为纯音频通话', 4000);
      const answerSdp = await media.handleOffer(window._incomingSdp);
      await invoke('answer', answerSdp);
      callState = 'active';
      $('incomingBox').classList.add('hidden');
      $('callControls').classList.remove('hidden');
      setStatus(media.videoAvailable ? '通话中' : '通话中（纯音频）', 'live');
      wireMediaCallbacks();
    } catch (e) {
      try { await invoke('reject', 'no-media'); } catch { /* ignore */ }
      endUiCall();
      setStatus(`接听失败：${e.message}`, 'err');
      toast(e.message, 5000);
    }
  };

  $('rejectBtn').onclick = async () => {
    try { await invoke('reject', 'declined'); } catch { /* ignore */ }
    $('incomingBox').classList.add('hidden');
    callState = 'idle';
    setStatus('已拒接');
  };

  $('hangupBtn').onclick = async () => {
    try { await invoke('hangup'); } catch { /* ignore */ }
    endUiCall();
    setStatus('已挂断');
  };

  $('muteBtn').onclick = () => {
    muted = !muted;
    media.setAudioMuted(muted);
    $('muteBtn').textContent = muted ? '🔈 取消静音' : '🔇 静音';
  };
  $('videoBtn').onclick = () => {
    videoOff = !videoOff;
    media.setVideoOff(videoOff);
    $('videoBtn').textContent = videoOff ? '🎥 打开视频' : '🎥 关闭视频';
  };
}

function wireMediaCallbacks() {
  media.onIceCandidate = (c) => { invoke('sendIce', c.toJSON()).catch(() => {}); };
  media.onRemoteStream = (stream) => { $('remoteVideo').srcObject = stream; };
  media.onIceState = (st) => {
    if (st === 'disconnected' || st === 'failed') {
      setStatus('连接中断：对方可能已离线或网络异常', 'err');
      toast('通话连接中断');
    } else if (st === 'connected' || st === 'completed') {
      setStatus('通话中', 'live');
    }
  };
}

function endUiCall() {
  stopMicMeter();
  media.close();
  $('localVideo').srcObject = null;
  $('remoteVideo').srcObject = null;
  $('callControls').classList.add('hidden');
  $('incomingBox').classList.add('hidden');
  callState = 'idle';
  muted = false;
  videoOff = false;
  $('muteBtn').textContent = '🔇 静音';
  $('videoBtn').textContent = '🎥 关闭视频';
}

function hidePairIncoming() {
  $('pairIncomingBox').classList.add('hidden');
  $('pairAcceptBtn').disabled = false;
  $('pairRejectBtn').disabled = false;
}

function hideSasBox() {
  $('pairCodeBox').classList.add('hidden');
  $('sasOkBtn').disabled = false;
  $('sasNoBtn').disabled = false;
}

// ---------- 主进程事件 ----------
function handleEvent(name, p) {
  switch (name) {
    case 'pair:sas':
      $('pairCode').textContent = p.sas;
      $('pairCodeBox').classList.remove('hidden');
      setStatus('请与对方核对校验码是否一致');
      toast('请与对方核对 6 位校验码');
      break;
    case 'pair:incoming':
      $('pairFromName').textContent = p.deviceName || p.deviceId;
      $('pairIncomingBox').classList.remove('hidden');
      toast('收到配对请求');
      break;
    case 'pair:done':
      hideSasBox();
      hidePairIncoming();
      setStatus('空闲');
      toast(`✅ 配对成功：${p.deviceName || p.deviceId}`);
      invoke('getInfo').then((info) => renderPeers(info.pairedDevices || [])).catch(() => {});
      break;
    case 'pair:failed':
      hideSasBox();
      hidePairIncoming();
      setStatus('空闲');
      toast(`配对失败：${p.reason || '未知'}`);
      break;
    case 'security:alert':
      endUiCall();
      setStatus(`安全告警：${p.reason}，已断开连接`, 'err');
      toast(`安全告警：${p.reason}`, 6000);
      break;
    case 'call:incoming':
      if (callState !== 'idle') break; // 主进程已自动回 busy
      window._incomingSdp = p.sdp;
      $('incomingName').textContent = p.deviceName || p.deviceId;
      $('incomingBox').classList.remove('hidden');
      callState = 'ringing';
      setStatus('来电…');
      break;
    case 'call:accepted':
      media.handleAnswer(p.sdp).then(() => setStatus('通话中', 'live'))
        .catch((e) => { setStatus(`媒体协商失败：${e.message}`, 'err'); });
      callState = 'active';
      break;
    case 'call:rejected':
      endUiCall();
      setStatus(`对方${p.reason === 'busy' ? '正忙' : '拒绝了通话'}`, 'err');
      break;
    case 'call:ice':
      media.addIceCandidate(p.candidate);
      break;
    case 'call:hangup':
    case 'call:ended':
      endUiCall();
      setStatus(p.reason === 'connection-lost' ? '对方已断开' : '通话已结束');
      break;
    case 'call:failed':
      endUiCall();
      setStatus(`呼叫失败：${p.reason}`, 'err');
      toast(p.reason, 5000);
      break;
    case 'service:error':
      $('netStatus').textContent = '● 服务启动失败';
      $('netStatus').className = 'net-status err';
      toast(`信令服务启动失败：${p.error}`, 6000);
      break;
    default:
      break;
  }
}

document.addEventListener('DOMContentLoaded', init);

// LAN Call 媒体层（渲染进程）
// 职责：getUserMedia + RTCPeerConnection（无 STUN，只用局域网 host 候选）
// 不接触信令密钥；SDP/ICE 经 preload 白名单 IPC 交给主进程发送。

'use strict';

function mediaErrorToChinese(e) {
  const n = e && e.name;
  if (n === 'NotFoundError' || n === 'OverconstrainedError')
    return '未找到摄像头或麦克风：请确认设备已连接并在系统设置中允许访问。';
  if (n === 'NotAllowedError' || n === 'SecurityError')
    return '摄像头/麦克风权限被拒绝：请在系统隐私设置中允许本软件访问。';
  if (n === 'NotReadableError')
    return '设备被其他程序占用：请关闭占用摄像头/麦克风的软件后重试。';
  return `获取音视频设备失败：${e && e.message ? e.message : n || '未知错误'}`;
}

class MediaSession {
  constructor() {
    this.pc = null;
    this.localStream = null;
    this.videoAvailable = true; // 摄像头可用；被占用/不存在时降级为纯音频
    this.onIceCandidate = null; // (candidate) => void
    this.onRemoteStream = null; // (stream) => void
    this.onIceState = null;     // (state) => void
  }

  async ensureLocalStream() {
    if (this.localStream) return this.localStream;
    try {
      this.localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      this.videoAvailable = true;
    } catch (e) {
      // 摄像头被占用或不存在 → 降级纯音频（单机双开、摄像头被其他软件占用、无摄像头场景）
      const n = e && e.name;
      if (n === 'NotReadableError' || n === 'NotFoundError' || n === 'OverconstrainedError') {
        try {
          this.localStream = await navigator.mediaDevices.getUserMedia({ video: false, audio: true });
          this.videoAvailable = false;
        } catch (e2) {
          throw new Error(mediaErrorToChinese(e2));
        }
      } else {
        throw new Error(mediaErrorToChinese(e));
      }
    }
    return this.localStream;
  }

  _createPc() {
    // 局域网：不配 STUN/TURN，只用 host 候选
    this.pc = new RTCPeerConnection({ iceServers: [] });
    this.pc.onicecandidate = (ev) => {
      if (ev.candidate && this.onIceCandidate) this.onIceCandidate(ev.candidate);
    };
    this.pc.ontrack = (ev) => {
      if (this.onRemoteStream && ev.streams[0]) this.onRemoteStream(ev.streams[0]);
    };
    this.pc.oniceconnectionstatechange = () => {
      if (this.onIceState) this.onIceState(this.pc.iceConnectionState);
    };
    if (this.localStream) {
      for (const t of this.localStream.getTracks()) this.pc.addTrack(t, this.localStream);
    }
  }

  async makeOffer() {
    await this.ensureLocalStream();
    this._createPc();
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    return offer.sdp;
  }

  async handleOffer(sdp) {
    await this.ensureLocalStream();
    this._createPc();
    await this.pc.setRemoteDescription({ type: 'offer', sdp });
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    return answer.sdp;
  }

  async handleAnswer(sdp) {
    if (!this.pc) throw new Error('通话未初始化');
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
  }

  async addIceCandidate(candidate) {
    if (!this.pc) return;
    try {
      await this.pc.addIceCandidate(candidate);
    } catch {
      // 远端描述尚未就绪时的候选可安全忽略（trickle 竞态）
    }
  }

  setAudioMuted(muted) {
    if (!this.localStream) return;
    for (const t of this.localStream.getAudioTracks()) t.enabled = !muted;
  }

  setVideoOff(off) {
    if (!this.localStream) return;
    for (const t of this.localStream.getVideoTracks()) t.enabled = !off;
  }

  close() {
    try {
      if (this.pc) this.pc.close();
    } catch { /* ignore */ }
    this.pc = null;
    if (this.localStream) {
      for (const t of this.localStream.getTracks()) {
        try { t.stop(); } catch { /* ignore */ }
      }
    }
    this.localStream = null;
    this.videoAvailable = true;
  }
}

window.MediaSession = MediaSession;
window.mediaErrorToChinese = mediaErrorToChinese;

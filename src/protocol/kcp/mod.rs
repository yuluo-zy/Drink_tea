mod pcc;
mod timer;
mod window;

use crate::error::{TeaError, TeaResult};
use crate::protocol::kcp::pcc::{MonitorInterval, PCC};
use bytes::{Buf, BufMut};
use derivative::Derivative;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::convert::TryInto;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use timer::Timer;
use window::Window;

// bbr 性能改进
/// The overhead imposed by KCP per packet (aka. packet header length).
/// kcp 包头大小
const OVERHEAD: u32 = 20;
/// The upper bound for fragmentation of a long payload.
/// 最大分段
const MAX_FRAGMENTS: u16 = 128;

/// Gain cycles (x4) used in ProbeBW state of the BBR control algorithm.
const BBR_GAIN_CYCLE: [usize; 8] = [5, 3, 4, 4, 4, 4, 4, 4];
/// KCP BDP gain denominator
const BDP_GAIN_DEN: usize = 1024;
/// KCP Data Segment
#[derive(Default, Derivative)]
#[derivative(Debug)]
#[rustfmt::skip]
struct Segment {
    // 用户数据可能会被分成多个KCP包发送，frag标识segment分片ID（在message中的索引，由大到小，0表示最后一个分片）
    frg: u8,
    // message发送时刻的时间戳
    ts: u32,
    // message分片 segment的序号，按1累次递增。
    sn: u32,
    /// Retransmission Timeout
    /// 该分片的超时重传等待时间
    rto: u32,
    /// 数据包被跳过确认的次数。
    /// Number of times the packet is skip-ACKed.
    skip_acks: u32,
    /// 传输尝试次数
    /// Number of transmission attempts.
    sends: u32,
    // message发送时刻的时间戳
    ts_last_send: u32,
    #[derivative(Debug = "ignore")]
    payload: Vec<u8>,
    mi: Option<Rc<RefCell<MonitorInterval>>>,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
enum Command {
    Push = 81,
    Ack = 82,
    AskWnd = 83,
    TellWnd = 84,
}

/// KCP configuration.
/// All time-related items are in milliseconds.
#[derive(Clone, Debug, Deserialize, Derivative)]
#[derivative(Default)]
#[serde(default)]
pub struct Config {
    // mtu：最大传输单元，默认数据为1400，最小为50；
    #[derivative(Default(value = "1400"))]
    pub mtu: u32,
    // rx_rto：由ACK接收延迟计算出来的重传超时时间；
    #[derivative(Default(value = "200"))]
    pub rto_default: u32,
    #[derivative(Default(value = "100"))]
    pub rto_min: u32,
    #[derivative(Default(value = "6000"))]
    pub rto_max: u32,
    /// Initial & minimal probe timeout
    /// 初始和最小探测超时
    #[derivative(Default(value = "7000"))]
    pub probe_min: u32,
    /// Maximum probe timeout
    #[derivative(Default(value = "120000"))]
    pub probe_max: u32,
    #[derivative(Default(value = "1024"))]
    pub send_wnd: u16,
    #[derivative(Default(value = "1024"))]
    pub recv_wnd: u16,
    #[derivative(Default(value = "40"))]
    pub interval: u32,
    /// After failure of this many retransmission attempts, the link will be considered to be dead.
    #[derivative(Default(value = "20"))]
    pub dead_link_thres: u32,
    // 在 nodelay 模式下，rto_min = 0 并且 rto 不会呈指数增长。
    /// In nodelay mode, rto_min = 0 and rto does not exponentially grow.
    #[derivative(Default(value = "false"))]
    pub nodelay: bool,
    // 在流模式下，可以将多个数据报合并为一个段以减少开销
    /// In stream mode, multiple datagrams may be merged into one segment to reduce overhead.
    #[derivative(Default(value = "false"))]
    pub stream: bool,
    /// 在这么多跳过确认之后的段将立即重传。
    /// A segment after this many skip-acks will be retransmitted immediately.
    #[derivative(Default(value = "None"))]
    pub fast_resend_thres: Option<u32>,
    /// Cap the maximum # of fast retransmission attempts.
    #[derivative(Default(value = "None"))]
    pub fast_resend_limit: Option<u32>,
    /// Window length (unit: ms) for RTprop (Round-trip propagation time) filters in BBR.
    #[derivative(Default(value = "10000"))]
    pub rt_prop_wnd: u32,
    /// Window length (unit: RTT) for BtlBW (Bottleneck bandwidth) filters in BBR.
    #[derivative(Default(value = "10"))]
    pub btl_bw_wnd: u32,
    /// Time for one ProbeRTT phase.
    #[derivative(Default(value = "200"))]
    pub probe_rtt_time: u32,
    /// A multiplier than controls the aggressiveness of BBR. To avoid floating point arithmetic
    /// it is 1024-based e.g. set to 1024 for 1.0, 1536 for 1.5, and 2048 for 2.0 etc.
    #[derivative(Default(value = "1024"))]
    pub bdp_gain: usize,
    #[derivative(Default(value = "None"))]
    pub pcc: Option<pcc::Config>,
}

impl Config {
    #[inline(always)]
    pub fn mss(&self) -> usize {
        (self.mtu - OVERHEAD) as usize
    }
}

/// KCP control block with BBR congestion control.
///
/// This control block is **NOT** safe for concurrent access -- to do so please wrap it in a Mutex.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct KcpCore {
    /// Conversation ID.
    conv: u16,
    /// KCP Config (should be immutable)
    #[derivative(Debug = "ignore")]
    config: Arc<Config>,
    /// If the underlying link is dead
    dead_link: bool,
    /// Oldest Unacknowledged Packet in the send window.
    /// 发送窗口中最旧的未确认数据包。
    send_una: u32,
    /// Sequence number of the next packet to be sent.
    /// 下一个要发送的包
    send_nxt: u32,
    /// Sequence number of the next packet to be put in the receive queue.
    /// Sequence number of the next packet to be sent.
    recv_nxt: u32,
    /// Variance of RTT.
    /// RTT 的差异
    rtt_var: u32,
    /// Smooth RTT estimation.
    /// 平滑的 RTT 估计
    srtt: u32,
    /// Base retransmission timeout.
    rto: u32,
    /// Remote window size (packet).
    rmt_wnd: u16,
    /// Current timestamp (ms).
    now: u32,
    /// Timestamp for next flush.
    ts_flush: u32,
    /// Timestamp for next probe.
    ts_probe: u32,
    /// Whether we should ask the other side to tell us its window size.
    // 我们是否应该要求对方告诉我们它的窗口大小。
    probe_ask: bool,
    /// Whether we should tell the other side our window size.
    probe_tell: bool,
    /// Probing timeout.
    /// 探测超时
    probe_timeout: u32,
    /// Send queue, which stores packets that are enqueued but not in the send window.
    #[derivative(Debug = "ignore")]
    send_queue: VecDeque<Segment>,
    /// Receive queue, which stores packets that are received but not consumed by the application.
    #[derivative(Debug = "ignore")]
    recv_queue: VecDeque<Segment>,
    /// Send buffer, which stores packets sent but not yet acknowledged. 已发送未确认
    #[derivative(Debug = "ignore")]
    send_buf: Window<Segment>,
    /// Receive buffer, which stores packets that arrive but cannot be used because a preceding
    /// packet hasn't arrived yet.
    #[derivative(Debug = "ignore")]
    recv_buf: Window<Segment>,
    /// Timer to schedule packet transmission
    #[derivative(Debug = "ignore")]
    timer: Timer,
    /// Output queue, the outer application should actively poll from this queue.
    // 输出队列，外部应用程序应该主动从这个队列中轮询
    #[derivative(Debug = "ignore")]
    output: VecDeque<Vec<u8>>,
    /// Buffer used to merge small packets into a batch (thus making better use of bandwidth).
    // 缓冲区用于将小数据包合并为一个批次（从而更好地利用带宽）
    #[derivative(Debug = "ignore")]
    buffer: Vec<u8>,
    ///创建控制块的瞬间
    #[derivative(Debug = "ignore")]
    epoch: Instant,

    #[derivative(Debug = "ignore")]
    acks: VecDeque<(u32, u32)>,
    pcc: Option<PCC>,
    inflight: usize,
}

/// Actually Segment will not be sent between threads
unsafe impl Send for Segment {}

/// Actually ControlBlock will not be sent between threads
unsafe impl Send for KcpCore {}

/// States for the BBR congestion control algorithm.
///
/// Adapted from the appendix section of the original BBR paper.
#[derive(Debug)]
enum BBRState {
    /// Startup phase, in which BBR quickly discovers the bottleneck bandwidth.
    Startup,
    /// Drain phase used to drain the pipe over-filled by the previous start up phase.
    Drain,
    /// The main phase of BBR, in which BBR cycles through different gains in an attempt to probe
    /// the bottleneck bandwidth.
    ProbeBW(/* since */ u32, /* phase */ usize),
    /// In this phase, BBR drastically reduces the congestion window to accurately probe RT prop.
    ProbeRTT(/* since */ u32, /* phase */ usize),
}

impl KcpCore {
    /// Creates a new KCP control block with the given conversation ID and default parameters.
    pub fn new(conv: u16, config: Arc<Config>) -> TeaResult<Self> {
        Ok(KcpCore {
            conv,
            dead_link: false,
            send_una: 0,
            send_nxt: 0,
            recv_nxt: 0,
            rto: config.rto_default,
            rtt_var: 0,
            srtt: config.rto_default,
            rmt_wnd: config.recv_wnd,
            now: 0,
            ts_flush: config.interval,
            ts_probe: 0,
            probe_ask: false,
            probe_tell: false,
            probe_timeout: 0,
            send_queue: Default::default(),
            recv_queue: Default::default(),
            send_buf: Window::with_size(config.send_wnd as usize),
            recv_buf: Window::with_size(config.recv_wnd as usize),
            timer: Timer::with_capacity(config.send_wnd as usize),
            output: Default::default(),
            buffer: Vec::with_capacity(config.mtu as usize),
            epoch: Instant::now(),
            acks: Default::default(),
            inflight: 0,
            config: config.clone(),
            pcc: config
                .pcc
                .as_ref()
                .map(|conf| PCC::new(conf.clone(), 0, config.rto_default)),
        })
    }

    // 查看下一个数据包的大小。如果当前接收缓冲区中没有数据包，则返回错误。
    pub fn peek_size(&self) -> TeaResult<usize> {
        let seg = self.recv_queue.front().ok_or(TeaError::NotAvailable)?;
        if seg.frg == 0 {
            return Ok(seg.payload.len());
        }
        if self.recv_queue.len() < (seg.frg + 1) as usize {
            // 说明还没有接收完这个数据包所有分片
            return Err(TeaError::NotAvailable);
        }
        let mut len = 0;
        for seg in &self.recv_queue {
            len += seg.payload.len();
            if seg.frg == 0 {
                break;
            }
        }
        Ok(len)
    }

    /// Receives a packet of data using this KCP control block.
    ///
    /// **Note**: if [stream mode](#structfield.stream) is off (by default), then one receive
    /// corresponds to one [send](#method.send) on the other side. Otherwise, this correlation
    /// may not hold as in stream mode KCP will try to merge payloads to reduce overheads.
    /// 使用此 KCP 控制块接收数据包。注意：如果 [stream mode](structfield.stream) 关闭（默认），
    /// 那么一个接收对应另一侧的一个 [send](method.send)。否则，这种相关性可能不成立，
    /// 因为在流模式下 KCP 将尝试合并有效负载以减少开销。
    #[inline]
    pub fn recv(&mut self) -> TeaResult<Vec<u8>> {
        let size = self.peek_size()?;
        /// TODO 修改为零内存拷贝
        let mut ret = Vec::with_capacity(size);
        while !self.recv_queue.is_empty() {
            let mut seg = self.recv_queue.pop_front().unwrap();
            ret.append(&mut seg.payload);
            if seg.frg == 0 {
                break;
            }
        }
        assert_eq!(size, ret.len());
        Ok(ret)
    }

    /// Sends some data using this KCP control block.
    ///
    /// **Note**: if [stream mode](#structfield.stream) is off (by default), then one send
    /// corresponds to one [receive](#method.recv) on the other side. Otherwise, this correlation
    /// may not hold as in stream mode KCP will try to merge payloads to reduce overheads.
    ///
    /// **Note**: After calling this do remember to call [check](#method.check), as
    /// an input packet may invalidate previous time estimations of the next update.
    ///
    /// 使用此 KCP 控制块发送一些数据。注意：如果 [stream mode](structfield.stream) 关闭（默认），
    /// 那么一个发送对应另一侧的一个 [receive](method.recv)。否则，这种相关性可能不成立，
    /// 因为在流模式下 KCP 将尝试合并有效负载以减少开销。注意：调用后记得调用 [check](method.check)，
    /// 因为输入数据包可能会使下一次更新的先前时间估计无效。
    ///
    #[inline]
    pub fn send(&mut self, mut buf: &[u8]) -> TeaResult<()> {
        let mss = self.config.mss();
        if self.config.stream {
            if let Some(old) = self.send_queue.back_mut() {
                if old.payload.len() < mss {
                    let cap = mss - old.payload.len();
                    let extend = min(cap, buf.len());
                    let (front, back) = buf.split_at(extend);
                    old.payload.extend_from_slice(front);
                    old.frg = 0;
                    buf = back;
                }
                if buf.is_empty() {
                    return Ok(());
                }
            }
        }
        let count = if buf.len() <= mss {
            1
        } else {
            (buf.len() + mss - 1) / mss
        };
        if count > MAX_FRAGMENTS as usize {
            return Err(TeaError::OversizePacket);
        }
        assert!(count > 0);
        if self.config.stream {
            for i in 0..count {
                let size = min(mss, buf.len());
                let (front, back) = buf.split_at(size);
                self.send_queue.push_back(Segment {
                    frg: 0,
                    payload: front.into(),
                    ..Default::default()
                });
                buf = back;
            }
        } else {
            for i in 0..count {
                let size = min(mss, buf.len());
                let (front, back) = buf.split_at(size);
                self.send_queue.push_back(Segment {
                    frg: (count - i - 1) as u8,
                    payload: front.into(),
                    ..Default::default()
                });
                buf = back;
            }
        }

        // self.sync_now();
        self.flush_push();
        Ok(())
    }

    /// Updates the RTT filter and recalculates RTO according to RFC 6298.
    /// 根据 RFC 6298 更新 RTT 过滤器并重新计算 RTO
    #[inline]
    fn update_rtt_filters(&mut self, rtt: u32) {
        if self.srtt == 0 {
            self.srtt = rtt;
            self.rtt_var = rtt / 2;
        } else {
            let delta = diff(rtt, self.srtt);
            self.rtt_var = (3 * self.rtt_var + delta) / 4;
            self.srtt = max(1, (7 * self.srtt + rtt) / 8);
        }
        // 计算基础超时时间
        let rto = self.srtt + max(self.config.interval, 4 * self.rtt_var);
        self.rto = max(self.config.rto_min, min(rto, self.config.rto_max));
    }

    /// Recalculates UNA based on the current [send buffer](#structfield.send_buf).
    /// 根据当前的[发送缓冲区](structfield.send_buf)重新计算UNA
    fn update_una(&mut self) {
        // 计算最老的包 尚未被 ack
        // 发送方 更新
        self.send_una = self.send_buf.front().map_or(self.send_nxt, |seg| seg.sn);
    }

    /// Updates BBR filters and relevant fields when a packet is acknowledged, roughly equivalent to
    /// the `onAck` function in the BBR paper.
    /// 当数据包被确认时更新 BBR 过滤器和相关字段，大致相当于 BBR 论文中的“onAck”功能。
    fn on_ack(&mut self, seg: &Segment) {
        self.inflight = self
            .inflight
            .saturating_sub(seg.payload.len() + OVERHEAD as usize);
        let rtt = max(self.now - seg.ts_last_send, 1);
        self.update_rtt_filters(rtt);
        if let Some(pcc) = &mut self.pcc {
            pcc.on_ack(&seg);
            pcc.update(self.now, self.srtt);
        }
    }

    /// Removes the packet from the [send buffer](#structfield.send_buf) whose sequence number is `sn`
    /// marks it as acknowledged.
    /// 从 [send buffer](structfield.send_buf) 中移除序列号为 `sn` 的数据包，将其标记为已确认。
    fn ack_packet_with_sn(&mut self, sn: u32, _ts: u32) {
        // 去除 ack 的包
        if self.send_una <= sn && sn < self.send_nxt {
            if let Some(seg) = self.send_buf.remove(sn as usize) {
                self.on_ack(&seg);
            }
        }
    }

    /// Removes packets from the [send buffer](#structfield.send_buf) whose sequence number is less
    /// than `una` and marks them as acknowledged.
    /// 从 [send buffer](structfield.send_buf) 中删除序列号小于 `una` 的数据包，并将它们标记为已确认。
    fn ack_packets_before_una(&mut self, una: u32) {
        while matches!(self.send_buf.front(), Some(seg) if seg.sn < una) {
            let seg = self.send_buf.pop_unchecked();
            self.on_ack(&seg);
        }
    }

    /// Increases the skip-ACK count of packets with sequence number less than `sn` (useful in KCP
    /// fast retransmission).
    /// 增加序列号小于 `sn` 的数据包的跳过 ACK 计数（在 KCP 快速重传中很有用）。
    fn increase_skip_acks(&mut self, sn: u32) {
        // 在本次 ack 的时候 如果有比本序列号小的, 那我就直接加一, 用于快速重传
        // 是 sn 而不是 una
        if self.send_una <= sn && sn < self.send_nxt {
            // Copy values from self to keep Rust borrow checker happy
            let fast_resend_thres = self.config.fast_resend_thres;
            let fast_resend_limit = self.config.fast_resend_limit;
            let timer = &mut self.timer;
            let now = self.now;
            self.send_buf.for_preceding(sn as usize, |seg| {
                seg.skip_acks += 1;
                if fast_resend_thres.map_or(false, |thres| seg.skip_acks == thres)
                    && fast_resend_limit.map_or(true, |limit| seg.sends <= limit)
                {
                    seg.ts = now;
                    timer.schedule(now, seg.sn);
                }
            });
        }
    }

    /// Pushes a segment onto the [receive buffer](#structfield.recv_buf), and if possible, moves
    /// segments from the receiver buffer to the [receive queue](#structfield.recv_queue).
    /// 将一个段推送到[接收缓冲区](structfield.recv_buf)，
    /// 如果可能，将段从接收器缓冲区移动到[接收队列](structfield.recv_queue)
    fn push_segment(&mut self, seg: Segment) {
        self.recv_buf.push(seg.sn as usize, seg);
        // Move packets from the buffer to the receive queue if possible
        while !self.recv_buf.is_empty() && self.recv_queue.len() < self.config.recv_wnd as usize {
            // 是接受队列的下一个接受者
            match self.recv_buf.remove(self.recv_nxt as usize) {
                Some(seg) => {
                    self.recv_queue.push_back(seg);
                    self.recv_nxt += 1;
                }
                None => break,
            }
        }
    }

    /// Feeds a raw packet from the underlying protocol stack into the control block.
    ///
    /// Returns the total number of bytes that is actually considered valid by KCP.
    ///
    /// **Note**: After calling this do remember to call [check](#method.check), as
    /// an input packet may invalidate previous time estimations of the next update.
    ///
    /// 将来自底层协议栈的原始数据包送入控制块。返回 KCP 实际认为有效的总字节数。
    /// 注意：调用后记得调用 [check](method.check)，
    /// 因为输入数据包可能会使下一次更新的先前时间估计无效
    #[instrument(skip(self, data), fields(len = data.len()))]
    pub fn input(&mut self, mut data: &[u8]) -> TeaResult<usize> {
        self.sync_now();
        let prev_len = data.len();
        let mut sn_max_ack = None;
        if data.len() < OVERHEAD as usize {
            return Err(TeaError::IncompletePacket);
        }
        while data.len() >= OVERHEAD as usize {
            let (mut header, body) = data.split_at(OVERHEAD as usize);
            // Read header
            let conv = header.get_u16_le();
            if conv != self.conv {
                return Err(TeaError::WrongConv {
                    expected: self.conv,
                    found: conv,
                });
            }
            let cmd = header.get_u8();
            let frg = header.get_u8();
            let wnd = header.get_u16_le();
            let ts = header.get_u32_le();
            let sn = header.get_u32_le();
            // 这是对 对方来说, 尚未接受到哪一个宝 需要接收的下一个包 也就是说 这个包我还没有可以 ack 掉
            let una = header.get_u32_le();
            let len = header.get_u16_le() as usize;
            data = body;
            if data.len() < len {
                return Err(TeaError::IncompletePacket);
            }
            let cmd =
                Command::try_from_primitive(cmd).map_err(|_| TeaError::InvalidCommand(cmd))?;
            self.rmt_wnd = wnd;
            // 删除掉 una 之前的包 之前的包都已经 接受到了, 这个是最老的尚未接受到的包 相当于在 ack
            self.ack_packets_before_una(una);
            // 找到最老的还没有被 ack 的包
            self.update_una();
            match cmd {
                Command::Ack => {
                    self.ack_packet_with_sn(sn, ts);
                    /// 把单独的一个包 ack 掉
                    self.update_una(); // 找到最老的还没有被 ack 的包
                    sn_max_ack = Some(max(sn, sn_max_ack.unwrap_or_default()));
                }
                Command::Push => {
                    // 回传 ack 标明已经接受到了
                    if sn < self.recv_nxt + self.config.recv_wnd as u32 {
                        self.acks.push_back((sn, ts));
                        if sn >= self.recv_nxt {
                            // 发送到接收缓冲区
                            self.push_segment(Segment {
                                sn,
                                frg,
                                payload: data[..len].into(),
                                ..Default::default()
                            });
                        }
                    }
                }
                Command::AskWnd => self.probe_tell = true,
                Command::TellWnd => {}
            }
            // 这是针对 流传输的解包操作
            data = &data[len..];
        }
        if let Some(sn) = self.config.fast_resend_thres.and(sn_max_ack) {
            // 针对跳过的 开始 ack 掉
            self.increase_skip_acks(sn)
        }
        self.flush_push();
        Ok(prev_len - data.len())
    }

    /// Polls an output packet that can be directly sent with the underlying protocol stack.
    ///
    /// Packet size is guaranteed to be at most the configured MTU.
    /// 轮询一个可以直接与底层协议栈一起发送的输出数据包。数据包大小最多保证为配置的 MTU。
    pub fn output(&mut self) -> Option<Vec<u8>> {
        self.output.pop_front()
    }

    /// Updates the probing state, recalculating the probing timeout if necessary.
    /// 更新探测状态，必要时重新计算探测超时。
    fn update_probe(&mut self) {
        if self.rmt_wnd == 0 {
            if self.probe_timeout == 0 {
                // If we are not probing, start probing window size
                // 如果我们不在探测，开始探测窗口大小
                self.probe_timeout = self.config.probe_min;
                self.ts_probe = self.now + self.probe_timeout;
            } else if self.now >= self.ts_probe {
                // Increase probe timeout by 1.5x until we know the window size
                self.probe_timeout = max(self.probe_timeout, self.config.probe_min);
                self.probe_timeout += self.probe_timeout / 2;
                self.probe_timeout = min(self.probe_timeout, self.config.probe_max);
                self.ts_probe = self.now + self.probe_timeout;
                self.probe_ask = true;
            }
        } else {
            self.probe_timeout = 0;
            self.ts_probe = 0;
        }
    }

    /// Flushes a segment header
    /// 刷新段头 写入要发送的地方
    fn flush_segment(&mut self, cmd: Command, frg: u8, sn: u32, ts: u32, len: usize) {
        let wnd = self
            .config
            .recv_wnd
            .saturating_sub(self.recv_queue.len() as u16);
        if self.buffer.len() + len + OVERHEAD as usize > self.config.mtu as usize {
            let mut new_buf = Vec::with_capacity(self.config.mtu as usize);
            std::mem::swap(&mut self.buffer, &mut new_buf);
            self.output.push_back(new_buf);
        }
        // 这里我改了两个地方 一个 是 会话总数 一个是是 包长度
        self.buffer.put_u16_le(self.conv);
        self.buffer.put_u8(cmd.into());
        self.buffer.put_u8(frg);
        self.buffer.put_u16_le(wnd);
        self.buffer.put_u32_le(ts);
        self.buffer.put_u32_le(sn);
        self.buffer.put_u32_le(self.recv_nxt);
        self.buffer.put_u16_le(len as u16);
    }

    /// Flush all window-probing-related segments
    /// 刷新所有与窗口探测相关的段
    fn flush_probe(&mut self) {
        // 开始探测对面的 窗口大小
        self.update_probe();
        if self.probe_ask {
            self.flush_segment(Command::AskWnd, 0, 0, 0, 0);
            self.probe_ask = false;
        }
        if self.probe_tell {
            self.flush_segment(Command::TellWnd, 0, 0, 0, 0);
            self.probe_tell = false;
        }
    }

    /// Calculate the congestion limit based on BBR.
    /// 基于BBR计算拥塞限制。
    fn calc_inflight_limit(&mut self) -> usize {
        // Because we are not really pacing the packets, the sending logic is different from what
        // is stated in the original BBR paper. The original BBR uses two parameters: cwnd_gain
        // and pacing_gain. However, the effects of the two parameters are hard to distinguish when
        // packets are flushed. Thus, it may be better to merge the two parameters into one here.
        // 为我们并没有真正对数据包进行 pacing，
        // 所以发送逻辑与原始 BBR 论文中陈述的不同。
        // 原始 BBR 使用两个参数：cwnd_gain 用于计算拥塞窗口(cwnd)的BDP的动态增益系数 和
        // pacing_gain。 用于计算 当前BBR流的pacing rate，用于控制发包间距。 的BBR.BtlBw的动态增益系数。
        // 然而，当数据包被刷新时，这两个参数的影响很难区分。因此，在这里将两个参数合二为一可能会更好。
        if let Some(pcc) = &mut self.pcc {
            pcc.update(self.now, self.srtt);
            (pcc.rate() * self.srtt as f64).round() as usize
        } else {
            usize::MAX
        }
    }

    /// Prepare a segment for (re)transmission
    /// 为（重新）传输准备一个段
    #[rustfmt::skip]
    fn prepare_send(&self, seg: &mut Segment) -> u32 {
        seg.sends += 1;
        seg.ts = self.now;
        // First retransmission
        if seg.sends == 1 {
            seg.rto = self.rto;
            seg.skip_acks = 0;
            if self.config.nodelay {
                self.now + seg.rto
            } else {
                self.now + seg.rto + self.config.rto_min
            }
        } else if self.config.fast_resend_thres
            .map_or(false, |thres| seg.skip_acks >= thres)
            && self.config.fast_resend_limit
            .map_or(true, |limit| seg.sends <= limit)
        {
            // Fast retransmission
            seg.skip_acks = 0;
            self.now + seg.rto
        } else {
            // Regular retransmission
            seg.rto = if self.config.nodelay {
                max(seg.rto, self.rto)
            } else {
                // Increase RTO by 1.5x, better than 2x in TCP
                seg.rto + seg.rto / 2
            };
            self.now + seg.rto
        }
    }

    /// Attempts to pull enqueued send segments into the send buffer, and to (re)transmit them if ne
    /// cessary
    /// 尝试将排队的发送段拉入发送缓冲区，并在必要时（重新）传输它们
    fn flush_push(&mut self) {
        let limit = self.calc_inflight_limit();
        // debug!(conv = self.conv, limit = limit);
        let cwnd = min(self.config.send_wnd, self.rmt_wnd);
        self.sync_now();
        while self.send_nxt < self.send_una + cwnd as u32
            && !self.send_queue.is_empty()
            && self.inflight <= limit
        // 还可以发送多少字节
        {
            let mut seg = self.send_queue.pop_front().unwrap();
            seg.sn = self.send_nxt;
            self.send_nxt += 1;
            self.inflight += seg.payload.len() + OVERHEAD as usize;
            seg.ts = self.now;
            self.timer.schedule(self.now, seg.sn);
            self.send_buf.push(seg.sn as usize, seg);
        }

        let mut send_buf = std::mem::take(&mut self.send_buf);
        while let Some((ts, sn)) = self.timer.event(self.now) {
            if sn < self.send_una || sn >= self.send_nxt {
                continue;
            }
            if let Some(seg) = send_buf.get_mut(sn as usize) {
                if ts == seg.ts {
                    if let Some(pcc) = &mut self.pcc {
                        if seg.sends >= 1 {
                            pcc.on_loss(seg);
                            pcc.update(self.now, self.srtt);
                        }
                        pcc.prepare_send(seg);
                    }
                    seg.ts = self.prepare_send(seg);
                    seg.ts_last_send = ts;
                    self.dead_link |= seg.sends >= self.config.dead_link_thres;
                    self.flush_segment(Command::Push, seg.frg, seg.sn, ts, seg.payload.len());
                    self.buffer.extend_from_slice(&seg.payload);
                    self.timer.schedule(seg.ts, seg.sn);
                }
            }
        }
        self.send_buf = send_buf;
    }

    fn flush_ack(&mut self) {
        for (sn, ts) in std::mem::take(&mut self.acks) {
            self.flush_segment(Command::Ack, 0, sn, ts, 0);
        }
    }

    /// Flushes packets from the [send queue](#structfield.send_queue) to the
    /// [send buffer](#structfield.send_buf), and (re)transmits the packets in the send buffer
    /// if necessary.
    /// 将数据包从 [发送队列](structfield.send_queue) 刷新到 [发送缓冲区](structfield.send_buf)，
    /// 并在必要时（重新）传输发送缓冲区中的数据包。
    #[instrument(skip(self))]
    pub fn flush(&mut self) {
        self.sync_now();
        self.flush_probe();
        self.flush_push();
        self.flush_ack();
        if !self.buffer.is_empty() {
            let mut new_buf = Vec::with_capacity(self.config.mtu as usize);
            std::mem::swap(&mut self.buffer, &mut new_buf);
            self.output.push_back(new_buf);
        }
    }

    fn sync_now(&mut self) {
        self.now = self.epoch.elapsed().as_millis() as u32;
    }

    /// Gets the number of packets wait to be sent. This includes both unsent packets and packets
    /// that have been sent but not acknowledged by the other side.
    /// 获取等待发送的数据包数。这包括未发送的数据包和已发送但未被对方确认的数据包。
    pub fn wait_send(&self) -> usize {
        self.send_buf.len() + self.send_queue.len()
    }

    /// Checks if everything is flushed, including unsent data packets and ACK packets.
    ///
    /// You may want to call this when you are about to drop this control block, to check if KCP has
    /// finished everything up.
    /// 检查所有内容是否已刷新，包括未发送的数据包和 ACK 数据包。
    /// 当您将要删除此控制块时，您可能想调用它，以检查 KCP 是否已完成所有操作。
    pub fn all_flushed(&self) -> bool {
        self.send_buf.is_empty() && self.send_queue.is_empty() && self.buffer.is_empty()
    }

    pub fn dead_link(&self) -> bool {
        self.dead_link
    }

    pub fn conv(&self) -> u16 {
        self.conv
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn debug(&self) {
        if let Some(pcc) = &self.pcc {
            pcc.debug();
        }
    }
}

fn diff(x: u32, y: u32) -> u32 {
    if x >= y {
        x - y
    } else {
        y - x
    }
}

/// Gets the conversation id from a raw buffer.
///
/// Panics if `buf` has a length less than 4.
/// 从原始缓冲区获取对话 ID。如果 `buf` 的长度小于 4，则会出现恐慌
pub fn conv_from_raw(buf: &[u8]) -> u32 {
    u32::from_le_bytes(buf[..4].try_into().unwrap())
}

/// Check if the given raw buffer `buf` contains the first PUSH packet, which marks the start
/// of a new connection.
/// 检查给定的原始缓冲区 `buf` 是否包含第一个 PUSH 数据包，它标志着新连接的开始。
pub fn first_push_packet(mut buf: &[u8]) -> bool {
    while buf.len() >= OVERHEAD as usize {
        let _conv = buf.get_u32_le();
        let cmd = buf.get_u8();
        let _frg = buf.get_u8();
        let _wnd = buf.get_u16_le();
        let _ts = buf.get_u32_le();
        let sn = buf.get_u32_le();
        let _una = buf.get_u32_le();
        let len = buf.get_u32_le() as usize;
        if cmd == Command::Push as u8 {
            return sn == 0;
        }
        buf = &buf[len..];
    }
    true
}

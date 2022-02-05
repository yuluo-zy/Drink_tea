use std::{
    cmp,
    collections::{HashMap, VecDeque},
    sync::Arc,
    task::{Context, Poll, Waker},
    time::SystemTime,
};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use smol::channel::Sender;

use crate::{
    error::{KcpError, KcpResult},
    segment::{KcpSegment, CMD_ACK, CMD_PING, CMD_PUSH, HEADER_SIZE},
};

pub const RTO_INIT: u32 = 200;
pub const SSTHRESH_MIN: u16 = 2;
pub const MIN_WINDOW_SIZE: u16 = 0x10;
pub const MAX_WINDOW_SIZE: u16 = 0x8000;

#[async_trait::async_trait]
pub trait KcpIo {
    async fn send_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<()>;
    async fn recv_packet(&self) -> std::io::Result<Vec<u8>>;
}

#[inline(always)]
fn now_millis() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32
}

#[inline(always)]
fn i32diff(a: u32, b: u32) -> i32 {
    a as i32 - b as i32
}

#[inline(always)]
fn bound<T: Ord>(lower: T, v: T, upper: T) -> T {
    cmp::min(cmp::max(lower, v), upper)
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Congestion {
    None,
    KcpReno,
    LossTolerance,
}

#[cfg(feature = "serde_support")]
impl<'de> serde::Deserialize<'de> for Congestion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        match name.as_str() {
            "none" => Ok(Self::None),
            "reno" => Ok(Self::KcpReno),
            "loss_tolerance" => Ok(Self::LossTolerance),
            _ => Ok(Self::LossTolerance),
        }
    }
}

bitflags! {
    struct CloseFlags: u8 {
        const TX_CLOSING = 0b00000001;
        const TX_CLOSED = 0b00000011;
        const RX_CLOSED = 0b00000100;
        const CLOSED = Self::TX_CLOSED.bits | Self::RX_CLOSED.bits;
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde_support", derive(serde_derive::Deserialize))]
pub struct KcpConfig {
    pub max_interval: u32,
    // 最大间隔
    pub min_interval: u32,
    // 最小间隔
    pub nodelay: bool,

    pub mtu: usize,
    pub mss: usize, // // mss：MSS（Maximum Segment Size），最大报文长度

    pub fast_rexmit_thresh: u32,
    // 快重传值
    pub fast_ack_thresh: u32,
    // 快速 ack 阈值
    pub congestion: Congestion,
    // 拥塞标志
    pub max_rexmit_time: u32,
    // 快重传时间
    pub min_rto: u32,

    pub send_window_size: u16,
    // 发送窗口大小
    pub recv_window_size: u16,
    // 接受窗口时间
    pub timeout: u32,
    //超时时间
    pub keep_alive_interval: u32,
    // 心跳检测
    pub name: String,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            min_interval: 10,
            max_interval: 100,
            nodelay: false,
            mtu: 1400 - 28,
            mss: 1400 - 28 - HEADER_SIZE,
            fast_rexmit_thresh: 16, //重传阈值
            fast_ack_thresh: 32,
            congestion: Congestion::LossTolerance,
            max_rexmit_time: 0x800,
            min_rto: 20,
            send_window_size: 0x1000,
            recv_window_size: 0x1000,
            timeout: 30000,
            keep_alive_interval: 1500,
            name: "".to_string(),
        }
    }
}

impl KcpConfig {
    pub fn check(&self) -> KcpResult<()> {
        if self.min_interval > self.max_interval {
            return Err(KcpError::InvalidConfig(
                "min_interval > max_interval".to_string(),
            ));
        }
        if self.min_interval < 10 || self.min_interval >= 1000 {
            return Err(KcpError::InvalidConfig(
                "min_interval should be in range (10, 1000)".to_string(),
            ));
        }
        if self.send_window_size < MIN_WINDOW_SIZE || self.send_window_size > MAX_WINDOW_SIZE {
            return Err(KcpError::InvalidConfig(format!(
                "send_window_size should be in range ({}, {})",
                MIN_WINDOW_SIZE, MAX_WINDOW_SIZE
            )));
        }
        if self.recv_window_size < MIN_WINDOW_SIZE || self.recv_window_size > MAX_WINDOW_SIZE {
            return Err(KcpError::InvalidConfig(format!(
                "recv_window_size should be in range ({}, {})",
                MIN_WINDOW_SIZE, MAX_WINDOW_SIZE
            )));
        }
        if self.mss > self.mtu - HEADER_SIZE {
            return Err(KcpError::InvalidConfig(
                "mss > mtu - HEADER_SIZE".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "serde_support")]
    #[test]
    fn deserialize() {
        use super::*;
        let s = r#"
    max_interval = 10
    min_interval = 100
    nodelay = false
    mtu = 1350
    mss = 1331
    fast_rexmit_thresh = 3
    fast_ack_thresh = 32
    congestion = "loss_tolerance"
    max_rexmit_time = 32
    min_rto = 20
    send_window_size = 0x800
    recv_window_size = 0x800
    timeout = 5000
    keep_alive_interval = 1500
    "#;
        let config = toml::from_str::<KcpConfig>(s).unwrap();
        assert_eq!(config.max_interval, 10);
        assert_eq!(config.min_interval, 100);
        assert_eq!(config.congestion, Congestion::LossTolerance);
    }
}

struct SendingKcpSegment {
    // 加密部分
    segment: KcpSegment,
    rexmit_timestamp: u32,    //重传的时间戳。超过当前时间重发这个包
    rto: u32,                 // //超时重传时间，根据网络去定
    fast_rexmit_counter: u32, //快速重传机制，记录被跳过的次数，超过次数进行快速重传
    rexmit_counter: u32,      // 重传次数
}

// 连续ARQ协议

pub(crate) struct KcpCore {
    stream_id: u16,
    // queue 是实际要发送出去的数据 由上层 应用层掺入
    send_queue: VecDeque<BytesMut>,
    send_window: VecDeque<SendingKcpSegment>,
    // queue 是 实际接受到的数据流 并要提交到上层应用层的数据
    recv_queue: VecDeque<Bytes>,
    recv_window: HashMap<u32, KcpSegment>,
    // windows 是底层的数据存放容器
    // 接受窗口
    ack_list: VecDeque<(u32, u32)>,
    // 还没有 ack 的下一个 最小的未ack序列号，即这个编号前面的所有报都收到了的标志
    send_unack: u32,
    send_next: u32,

    // 需要接收的下一个
    recv_next: u32,

    remote_window_size: u16,
    congestion_window_size: u16,    // 拥塞窗口大小
    congestion_window_bytes: usize, // 拥塞窗口字节
    slow_start_thresh: u16,         // 慢启动阈值

    srtt: u32,
    rttval: u32,
    rto: u32,
    // rx_rttval：RTT的平均偏差
    // rx_srtt：RTT的一个加权RTT平均值，平滑值。
    // RTT：Round-Trip Time，数据往返时间，即发出消息到接收到对端消息应答之间的时间差。
    // RTO：Retransmission TimeOut，重传超时时间，根据收集到的RTT时间估算。
    now: u32,
    ping_ts: u32,

    close_state: CloseFlags,
    close_moment: u32,

    buffer: Vec<u8>,

    pub config: Arc<KcpConfig>,

    send_waker: Option<Waker>, // 发送唤醒器
    recv_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    close_waker: Option<Waker>,

    // Waker 是一个句柄，用于通过通知其执行者它已准备好运行来唤醒任务。
    // 这个句柄封装了一个 [RawWaker] 实例，它定义了特定于执行程序的唤醒行为
    flush_notify_tx: Sender<()>,

    last_active: u32,

    push_counter: u32,
    rexmit_counter: u32,
    last_measure: u32, // 最后措施
}

impl Drop for KcpCore {
    fn drop(&mut self) {
        log::trace!("kcp core dropped");
        self.force_close();
    }
}

// 协议栈 实现
impl KcpCore {
    #[inline]
    pub fn get_stream_id(&self) -> u16 {
        self.stream_id
    }

    pub fn force_close(&mut self) {
        self.close_state.set(CloseFlags::CLOSED, true);

        if let Some(waker) = self.send_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.flush_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.close_waker.take() {
            waker.wake();
        }
    }

    fn remove_send_window_until(&mut self, sequence: u32) {
        // 删除发送窗口直到
        while self.send_window.len() != 0 {
            if i32diff(sequence, self.send_window.front().unwrap().segment.sequence) > 0 {
                self.send_window.pop_front();
            } else {
                break;
            }
        }
    }

    fn update_unack(&mut self) {
        self.send_unack = match self.send_window.front() {
            Some(sending_segment) => sending_segment.segment.sequence,
            None => self.send_next,
        }
    }

    fn update_rtt(&mut self, rtt: u32) {
        // 这个值最终会影响每个报文的超时发送时间
        // RTT是从发出一个包到接收到这个包的ACK的时间

        // srtt ack接收rtt平滑值 最近8次的平均值。
        // rttavl rtt平均值，为最近4次rtt的平均值 来回的平均值
        // rto：估算出来的rto值，为平滑值+max（interval，平均值）
        if self.srtt == 0 {
            // 当前没有rtt加权平均值
            // 以这次RTT值来设置
            self.srtt = rtt;
            // 平均值要除以2
            self.rttval = rtt / 2;
        } else {
            //  计算两者之差
            let delta = if rtt > self.srtt {
                rtt - self.srtt
            } else {
                self.srtt - rtt
            };
            // 算平均值，可以看到平均值是最近4次的平均
            self.rttval = (3 * self.rttval + delta) / 4;
            // 算加权值，加权值是最近8次加权值的平均
            self.srtt = (7 * self.srtt + rtt) / 8;
            // 不能小于1
            if self.srtt < 1 {
                self.srtt = 1;
            }
        }
        // 计算RTO值：平滑值+max（interval，平均值）
        let rto = self.srtt + cmp::max(self.config.max_interval, 4 * self.rttval);
        // 最终在[minrto, RTO_MAX]之间
        self.rto = bound(self.config.min_rto, rto, self.config.timeout);
        log::trace!("update srtt = {}, rto = {}", self.srtt, rto);
    }

    fn remove_from_send_window(&mut self, sequence: u32) {
        // Make sure send_unack <= seq < send_next
        if i32diff(sequence, self.send_unack) < 0 || i32diff(sequence, self.send_next) >= 0 {
            return;
        }

        for i in 0..self.send_window.len() {
            let segment_seq = self.send_window[i].segment.sequence;
            if sequence == segment_seq {
                self.send_window.remove(i);
                break;
            } else if sequence < segment_seq {
                break;
            }
        }
    }

    fn update_fast_rexmit(&mut self, sequence: u32) {
        // 这是 tcp 的 快速重传机制 :
        // 报文段1成功接收并被确认ACK 2，
        // 接收端的期待序号为2，当报文段2丢失，报文段3失序到来，与接收端的期望不匹配，接收端重复发送冗余ACK 2。
        // 如果在超时重传定时器溢出之前，接收到连续的三个重复冗余ACK（其实是收到4个同样的ACK，第一个是正常的，后三个才是冗余的），
        // 发送端便知晓哪个报文段在传输过程中丢失了，于是重发该报文段，

        // 这里是快速重传机制:
        // 当某个发送窗口中的包，若该包未接受到相应ACK包，
        // 但其后超过一定数量的包均得到ACK回复，则无需等待超时直接重传。
        if i32diff(sequence, self.send_unack) < 0 || i32diff(sequence, self.send_next) >= 0 {
            return;
        }

        for sending_segment in &mut self.send_window {
            let segment_seq = sending_segment.segment.sequence;
            if i32diff(sequence, segment_seq) < 0 {
                break;
            } else if segment_seq != sequence {
                sending_segment.fast_rexmit_counter += 1;
            }
        }
    }

    fn handle_ack(&mut self, segment: &KcpSegment) {
        // 对端应答ack报
        let mut cursor = &segment.data[..];
        let mut max_ack = 0;
        let mut ack_num = 0;
        let old_send_unack = self.send_unack;

        while cursor.remaining() >= 8 {
            let timestamp = cursor.get_u32_le();
            let sequence = cursor.get_u32_le();

            // 更新 rtt 预估值
            if timestamp < self.now {
                self.update_rtt(self.now - timestamp);
            }
            // 从发送窗口中 删除对应数据
            self.remove_from_send_window(sequence);
            if sequence > max_ack {
                max_ack = sequence;
            }
            ack_num += 1;
        }

        // 更新 还没有 ack 的值 还没有 ack 的值 就是 发送窗口的第一个报文
        self.update_unack();

        // 更新 快重传的值位置
        self.update_fast_rexmit(max_ack);

        if self.send_unack > old_send_unack {
            // Some packets were sent and acked successfully
            // It's time to update cwnd 更新拥塞窗口
            match self.config.congestion {
                Congestion::None => {}
                Congestion::KcpReno => {
                    for _ in 0..ack_num / 2 {
                        // todo 去掉这个循环
                        if self.congestion_window_size < self.remote_window_size {
                            // 远程的滑动窗口 大于本地的拥塞窗口
                            let mss = self.config.mss;
                            if self.congestion_window_size < self.slow_start_thresh {
                                // Slow start
                                self.congestion_window_size += 1;
                                self.congestion_window_bytes += mss;
                            } else {
                                // Congestion control
                                // 拥塞窗口增量递增1/16；
                                self.congestion_window_bytes +=
                                    (mss * mss) / self.congestion_window_bytes + (mss / 16);
                                // 只有在拥塞窗口递增后不超过incr的情况下才允许加一
                                if (self.congestion_window_size + 1) as usize * mss
                                    <= self.congestion_window_bytes
                                {
                                    self.congestion_window_size += 1;
                                }
                            }

                            if self.congestion_window_size > self.remote_window_size {
                                self.congestion_window_size = self.remote_window_size;
                                self.congestion_window_bytes =
                                    self.remote_window_size as usize * mss;
                            }
                        } else {
                            break;
                        }
                    }
                }
                Congestion::LossTolerance => {}
            }
            log::trace!(
                "ack, cwnd = {}, incr = {}",
                self.congestion_window_size,
                self.congestion_window_bytes
            );
        }
        log::trace!("input ack");
    }

    fn handle_push(&mut self, segment: &KcpSegment) {
        if i32diff(
            segment.sequence,
            self.recv_next + self.config.recv_window_size as u32,
        ) < 0
        {
            // 这里是接受
            // 这里是等待 ack 的列表 添加  因为发送给 对端确认 表示我们已经收到
            self.ack_list
                .push_back((segment.timestamp, segment.sequence));
            if self.ack_list.len() >= self.config.fast_ack_thresh as usize {
                // 若状态机中积累的 ACK 数量过多，则跳过当前心跳间隔直接发送响应。
                let _ = self.flush_notify_tx.try_send(());
            }
            if i32diff(segment.sequence, self.recv_next) >= 0 {
                // 要确保接受的 是我们现在期待的下一个
                if !self.recv_window.contains_key(&segment.sequence) {
                    self.recv_window.insert(segment.sequence, segment.clone());
                }
                while self.recv_window.contains_key(&self.recv_next) {
                    let segment = self.recv_window.remove(&self.recv_next).unwrap();
                    // Empty payload, closing
                    log::trace!("empty payload, closing");
                    if segment.data.len() == 0 {
                        // No more data from the peer
                        // This is the last segment moved into send_queue
                        self.close_state.set(CloseFlags::RX_CLOSED, true);
                        // Try to close local tx
                        if !self.close_state.contains(CloseFlags::TX_CLOSING) {
                            self.close_state.set(CloseFlags::TX_CLOSING, true);
                            self.send_queue.push_back(BytesMut::new());
                        }
                        break;
                    }
                    self.recv_queue.push_back(segment.data);
                    self.recv_next += 1;
                }
            }
        }

        log::trace!("input push");
    }

    pub fn input(&mut self, segments: Vec<KcpSegment>) -> KcpResult<()> {
        // 这是输入的 也就是接收的
        self.now = now_millis();
        self.last_active = self.now;

        for segment in &segments {
            assert_eq!(segment.stream_id, self.stream_id);
            log::trace!("input segment: {:?}", segment);
            self.remote_window_size = segment.recv_window_size;
            // 接受窗口起始序号
            self.remove_send_window_until(segment.recv_next);
            self.update_unack();

            match segment.command {
                CMD_ACK => {
                    self.handle_ack(segment);
                }
                CMD_PUSH => {
                    self.handle_push(segment);
                }
                CMD_PING => {
                    log::trace!("input ping");
                }
                _ => unreachable!(),
            }
        }

        if self.close_state.contains(CloseFlags::TX_CLOSING)
            && self.send_window.is_empty()
            && self.send_queue.is_empty()
        {
            // The last empty packet was sent and acked by the peer
            log::trace!("TX_CLOSING to TX_CLOSED");
            self.close_state.set(CloseFlags::TX_CLOSED, true);
        }

        self.try_wake_stream();
        Ok(())
    }

    #[inline]
    fn try_wake_stream(&mut self) {
        if self.send_ready() && self.send_waker.is_some() {
            let waker = self.send_waker.take().unwrap();
            log::trace!("waking send task");
            waker.wake();
        }

        if self.recv_ready() && self.recv_waker.is_some() {
            let waker = self.recv_waker.take().unwrap();
            log::trace!("waking recv task");
            waker.wake();
        }

        if self.flush_ready() && self.flush_waker.is_some() {
            let waker = self.flush_waker.take().unwrap();
            log::trace!("waking flush task");
            waker.wake();
        }
    }

    #[inline]
    fn send_ready(&self) -> bool {
        self.send_queue.len() < self.config.send_window_size as usize
    }

    #[inline]
    fn recv_ready(&self) -> bool {
        !self.recv_queue.is_empty()
    }

    #[inline]
    fn flush_ready(&self) -> bool {
        self.send_queue.is_empty() && self.send_window.is_empty()
    }

    pub fn poll_send(&mut self, cx: &Context, payload: &[u8]) -> Poll<KcpResult<()>> {
        // send只是将待发送数据组装成KCP报文放到发送队列中了
        if self.close_state.contains(CloseFlags::TX_CLOSING) {
            return Poll::Ready(Err(KcpError::Shutdown(format!(
                "poll_send on a closing kcp core: {}",
                self.close_state.bits,
            ))));
        }

        self.now = now_millis();
        self.last_active = self.now;

        if self.send_ready() {
            let mss = self.config.mss;
            if self.send_queue.is_empty() {
                self.send_queue.push_back(BytesMut::with_capacity(mss));
            }

            let mut cursor = payload;

            while cursor.has_remaining() {
                if self.send_queue.back_mut().unwrap().len() < mss {
                    let back = self.send_queue.back_mut().unwrap();
                    let len = cmp::min(cursor.remaining(), mss - back.len());
                    back.extend_frm_slice(&cursor[..len]);
                    cursor.advance(len);
                } else {
                    self.send_queue.push_back(BytesMut::with_capacity(mss));
                }
            }

            Poll::Ready(Ok(()))
        } else {
            let _ = self.flush_notify_tx.try_send(());
            self.send_waker = Some(cx.waker().clone());
            log::trace!("poll_send pending");
            Poll::Pending
        }
    }

    pub fn poll_recv(&mut self, cx: &Context) -> Poll<KcpResult<VecDeque<Bytes>>> {
        // recv函数就负责将这些报文重新组装起来放入用户缓冲区返回给用户层
        self.now = now_millis();
        self.last_active = self.now;

        // 之所以这里还需要“组装”，是因为对端发送的数据由于超过MTU所以被KCP协议栈分成多个报文发送了。
        // 所以这里需要兼容多个分片的情况，如果待接收报文的所有分片没有接收完毕，那么不能处理。
        // 接收完毕或者不分片的情况下，就遍历这些报文将数据拷贝到缓冲区中。

        if self.recv_ready() {
            let queue = self.recv_queue.clone();
            self.recv_queue.clear();
            return Poll::Ready(Ok(queue));
        } else {
            if self.close_state.contains(CloseFlags::RX_CLOSED) {
                return Poll::Ready(Err(KcpError::Shutdown(format!(
                    "poll_recv on a closing kcp core: {}",
                    self.close_state.bits,
                ))));
            }
            log::trace!("poll_recv pending");
            self.recv_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn poll_flush(&mut self, cx: &Context) -> Poll<KcpResult<()>> {
        if self.close_state.contains(CloseFlags::TX_CLOSING) {
            return Poll::Ready(Err(KcpError::Shutdown(format!(
                "poll_recv on a closing kcp core: {}",
                self.close_state.bits,
            ))));
        }

        self.now = now_millis();
        self.last_active = self.now;

        if self.flush_ready() {
            Poll::Ready(Ok(()))
        } else {
            self.flush_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub fn try_close(&mut self) -> KcpResult<()> {
        self.now = now_millis();
        if self.close_state.contains(CloseFlags::TX_CLOSING) {
            Err(KcpError::Shutdown("kcp core is shutting down".to_string()))
        } else {
            log::trace!("trying to close kcp core..");
            self.close_state.set(CloseFlags::TX_CLOSING, true);
            self.send_queue.push_back(BytesMut::new());
            Ok(())
        }
    }

    pub fn poll_close(&mut self, cx: &Context) -> Poll<KcpResult<()>> {
        self.now = now_millis();
        if !self.close_state.contains(CloseFlags::TX_CLOSING) {
            self.close_state.set(CloseFlags::TX_CLOSING, true);
            // Empty payload
            self.send_queue.push_back(BytesMut::new());
            self.close_waker = Some(cx.waker().clone());
            log::trace!("poll_close set close flag..");
            Poll::Pending
        } else if self.close_state.contains(CloseFlags::CLOSED) {
            log::trace!("poll_close ready");
            Poll::Ready(Ok(()))
        } else {
            // TX_CLOSED/TX_CLOSING, !RX_CLOSED
            // Just waiting for notification
            if let Some(waker) = &self.close_waker {
                if !cx.waker().will_wake(waker) {
                    unreachable!();
                }
            }

            self.close_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    #[inline]
    async fn encode_segment<IO: KcpIo>(
        segment: &KcpSegment,
        buffer: &mut Vec<u8>,
        io: &IO,
        mtu: usize,
    ) -> KcpResult<()> {
        if buffer.len() + segment.encoded_len() > mtu {
            // 只有 buffer 够长之后
            // 才进行 io 写入
            io.send_packet(buffer).await?;
            buffer.clear();
        }
        segment.encode(buffer);
        Ok(())
    }

    async fn flush_ack<IO: KcpIo>(&mut self, writer: &IO) -> KcpResult<()> {
        if self.ack_list.is_empty() {
            return Ok(());
        }
        // AP-KCP将其压缩在同一个ACK包中，每增加一个ACK段只需8字节
        let mut data = BytesMut::new();
        data.resize(4 * 2 * self.ack_list.len(), 0);

        let mut cursor = &mut data[..];

        for (timestamp, sequence) in &self.ack_list {
            cursor.put_u32_le(*timestamp);
            cursor.put_u32_le(*sequence);
        }

        let segment = KcpSegment {
            stream_id: self.stream_id,
            command: CMD_ACK,
            recv_window_size: self.recv_window_unused(),
            recv_next: self.recv_next,
            sequence: 0,
            timestamp: 0,
            data: data.freeze(),
        };
        Self::encode_segment(&segment, &mut self.buffer, writer, self.config.mtu).await?;
        self.ack_list.clear();
        Ok(())
    }

    async fn flush_ping<IO: KcpIo>(&mut self, writer: &IO) -> KcpResult<()> {
        // 探测机制
        // 保持存活，用于替代窗口探查，同步窗口信息和保持连接活跃
        if i32diff(self.now, self.ping_ts) >= 0 {
            log::trace!("flushing ping");
            self.ping_ts = self.now + self.config.keep_alive_interval;
            let segment = KcpSegment {
                stream_id: self.stream_id,
                command: CMD_PING,
                recv_window_size: self.recv_window_unused(),
                recv_next: self.recv_next,
                sequence: self.send_next,
                timestamp: self.now,
                data: Bytes::new(),
            };
            Self::encode_segment(&segment, &mut self.buffer, writer, self.config.mtu).await?;
        }
        Ok(())
    }

    #[inline]
    fn recv_window_unused(&self) -> u16 {
        if self.recv_queue.len() < self.config.recv_window_size as usize {
            self.config.recv_window_size - self.recv_queue.len() as u16
        } else {
            0
        }
    }

    pub async fn flush<IO: KcpIo>(&mut self, io: &IO) -> KcpResult<()> {
        // 会判断上一次刷新（flush）时间与这次的间隔，来判断是否调用flush函数来完成工作
        // ikcp_flush函数本质就是根据当前的情况，封装KCP报文，将这些报文放到发送缓冲区snd_buf中
        self.now = now_millis();

        if i32diff(self.now, self.last_measure) >= 500 && self.push_counter >= 100 {
            // 超时丢包
            // 减小拥塞窗口 如果存在一定的丢包则 增加发送数据
            if let Congestion::LossTolerance = self.config.congestion {
                let loss_rate = self.rexmit_counter * 100 / self.push_counter;
                if loss_rate >= 15 {
                    self.congestion_window_size -= self.congestion_window_size / 4;
                } else if loss_rate <= 5 {
                    self.congestion_window_size += self.congestion_window_size / 4;
                }
                log::trace!("loss_rate = {}", loss_rate);
                self.congestion_window_size = bound(
                    MIN_WINDOW_SIZE,
                    self.congestion_window_size,
                    self.config.send_window_size,
                );
            }

            self.last_measure = self.now;
            self.rexmit_counter = 0;
            self.push_counter = 0;
        }

        // Keep working until the core is fully closed
        if self.close_state.contains(CloseFlags::CLOSED) {
            if self.close_moment == 0 {
                // Keep running for a while to ACK
                let wait = bound(100, self.rto * 2, self.config.timeout);
                self.close_moment = self.now + wait;
            } else if i32diff(self.now, self.close_moment) >= 0 {
                // It's time to shutdown
                self.force_close();
                return Err(KcpError::Shutdown("flushing a closed kcp core".to_string()));
            }
        }

        if i32diff(self.now, self.last_active) > self.config.timeout as i32 {
            // Inactive for a long time, shut it down immediately
            self.force_close();
            return Err(KcpError::Shutdown(
                "flushing a timeout kcp core".to_string(),
            ));
        }

        self.flush_ack(io).await?;
        self.flush_ping(io).await?;

        let mut final_window_size = cmp::min(self.config.send_window_size, self.remote_window_size);
        match self.config.congestion {
            Congestion::None => {}
            _ => {
                final_window_size = cmp::min(final_window_size, self.congestion_window_size);
            }
        }
        // 计算最终的发送窗口大小

        // 设定我们的接受窗口的大小
        let recv_window_unused = self.recv_window_unused();

        // Push data into sending window
        while i32diff(self.send_next, self.send_unack + final_window_size as u32) < 0 {
            match self.send_queue.pop_front() {
                Some(data) => {
                    let segment = KcpSegment {
                        stream_id: self.stream_id,
                        command: CMD_PUSH,
                        sequence: self.send_next,
                        timestamp: self.now,
                        recv_window_size: recv_window_unused,
                        recv_next: self.recv_next,
                        data: data.freeze(),
                    };
                    let sending_segment = SendingKcpSegment {
                        segment,
                        rexmit_timestamp: self.now,
                        rto: self.rto,
                        fast_rexmit_counter: 0,
                        rexmit_counter: 0,
                    };
                    self.send_next += 1;
                    self.send_window.push_back(sending_segment);
                }
                None => {
                    break;
                }
            }
        }

        let fast_rexmit_thresh = self.config.fast_rexmit_thresh;

        let rexmit_delay = if self.config.nodelay {
            0
        } else {
            self.rto >> 3
        };

        let mut rexmit = 0;
        let mut fast_rexmit = 0;

        for sending_segment in &mut self.send_window {
            let mut need_send = false;
            if sending_segment.rexmit_counter == 0 {
                // First time
                sending_segment.rto = self.rto;
                sending_segment.rexmit_timestamp = self.now + self.rto + rexmit_delay;
                need_send = true;
            } else if i32diff(self.now, sending_segment.rexmit_timestamp) >= 0 {
                // Timeout, rexmit
                // 因为超时发生的重传
                need_send = true;
                rexmit += 1;
                self.rexmit_counter += 1;
                // rto：用来计算重传超时时间的，
                // 这个值会增加：
                // 在非急速模式下，每次递增的值也是KCP协议栈估算出来的RTO值。（segment->rto += kcp->rx_rto;）
                // 急速模式下，每次递增的值也是KCP协议栈估算出来的RTO值的二分之一。（segment->rto += kcp->rx_rto / 2）
                if self.config.nodelay {
                    // ~ 1.5x rto
                    sending_segment.rto += self.rto / 2;
                } else {
                    // ~ 2x rto
                    sending_segment.rto += self.rto;
                }
                sending_segment.rexmit_timestamp = self.now + sending_segment.rto;
            } else if sending_segment.fast_rexmit_counter > fast_rexmit_thresh {
                // Fast rexmit
                // 发生快重传
                need_send = true;
                fast_rexmit += 1;
                sending_segment.fast_rexmit_counter = 0;
            }

            if need_send {
                self.push_counter += 1;
                sending_segment.rexmit_counter += 1;
                sending_segment.segment.timestamp = self.now;
                sending_segment.segment.recv_window_size = recv_window_unused;
                Self::encode_segment(
                    &sending_segment.segment,
                    &mut self.buffer,
                    io,
                    self.config.mtu,
                )
                .await?;
                if sending_segment.rexmit_counter >= self.config.max_rexmit_time {
                    log::trace!("retransmitted for too many times, closed");
                    self.force_close();
                    return Err(KcpError::NoResponse);
                }
            }
        }

        if !self.buffer.is_empty() {
            io.send_packet(&mut self.buffer).await?;
            self.buffer.clear();
        }

        if let Congestion::KcpReno = self.config.congestion {
            let mss = self.config.mss;
            if fast_rexmit > 0 {
                // Some ACK packets was skipped
                // 这里是 真正快重传的 拥塞窗口调整
                let inflight_packet = (self.send_next - self.send_unack) as u16;
                self.slow_start_thresh = cmp::max(inflight_packet / 2, SSTHRESH_MIN);
                self.congestion_window_size =
                    self.slow_start_thresh + self.config.fast_rexmit_thresh as u16;
                self.congestion_window_bytes = self.congestion_window_size as usize * mss;
                log::trace!(
                    "fast resent, cwnd = {}, incr = {}",
                    self.congestion_window_size,
                    self.congestion_window_bytes
                );
            }

            if rexmit > 0 {
                // Packet lost
                self.slow_start_thresh = cmp::max(self.congestion_window_size / 2, SSTHRESH_MIN);
                self.congestion_window_size = 1;
                self.congestion_window_bytes = mss;
                log::trace!(
                    "packet lost, cwnd = {}, incr = {}",
                    self.congestion_window_size,
                    self.congestion_window_bytes
                );
            }
        }

        self.try_wake_stream();
        Ok(())
    }

    #[inline]
    pub fn get_interval(&self) -> u32 {
        // 用来 评估 重传超时时间的
        // rx_rto：估算出来的rto值，为平滑值+max（interval，平均值
        let mut interval = self.config.max_interval;
        for i in &self.send_window {
            let delta = i32diff(self.now, i.rexmit_timestamp);
            if delta < 0 {
                return self.config.min_interval;
            }
            interval = cmp::min(delta as u32, interval);
        }
        interval = cmp::max(interval, self.config.min_interval);
        log::trace!("dynamic interval = {}", interval);
        interval
    }

    pub fn new(
        stream_id: u16,
        config: Arc<KcpConfig>,
        flush_notify_tx: Sender<()>,
    ) -> KcpResult<Self> {
        config.check()?;
        let now = now_millis();
        Ok(KcpCore {
            stream_id,
            config: config.clone(),
            send_queue: VecDeque::with_capacity(config.send_window_size as usize),
            send_window: VecDeque::with_capacity(config.send_window_size as usize),
            recv_queue: VecDeque::with_capacity(config.recv_window_size as usize),
            recv_window: HashMap::with_capacity(config.recv_window_size as usize),
            ack_list: VecDeque::with_capacity(config.recv_window_size as usize),
            send_unack: 0,
            send_next: 0,
            recv_next: 0,

            remote_window_size: config.recv_window_size,
            congestion_window_size: config.send_window_size,
            congestion_window_bytes: config.mss,
            slow_start_thresh: SSTHRESH_MIN,

            rto: RTO_INIT,
            srtt: 0,
            rttval: 0,

            now: now,
            ping_ts: 0,

            buffer: Vec::with_capacity(config.mtu * 2),

            send_waker: None,
            recv_waker: None,
            flush_waker: None,
            flush_notify_tx,
            close_state: CloseFlags::empty(),
            close_moment: 0,
            close_waker: None,

            last_active: now,

            push_counter: 0,
            rexmit_counter: 0,
            last_measure: now,
        })
    }
}

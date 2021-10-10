use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// A quick and dirty implementation of an efficient timer used to schedule packet (re)transmission
pub struct Timer(BinaryHeap<Reverse<u64>>);
/// 元组结构体

impl Timer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(BinaryHeap::with_capacity(capacity))
    }

    pub fn schedule(&mut self, ts: u32, sn: u32) {
        // 时间 和分段序号
        self.0.push(Reverse(((ts as u64) << 32) | sn as u64));
    }

    pub fn imminent(&self) -> u32 {
        // 查看 小根堆 堆顶
        match self.0.peek() {
            Some(&Reverse(val)) => (val >> 32) as u32,
            None => u32::MAX,
        }
    }

    pub fn event(&mut self, now: u32) -> Option<(u32, u32)> {
        let key = (now as u64 + 1) << 32;
        match self.0.peek() {
            Some(&Reverse(val)) if val < key => {
                let sn = val & (u32::MAX as u64);
                let ts = val >> 32;
                self.0.pop();
                Some((ts as u32, sn as u32))
            }
            _ => None,
        }
    }
}

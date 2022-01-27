use std::sync::Arc;

pub mod allow_ips;
pub mod labels;
pub use self::allow_ips::AllowIps;
pub use tea_proxy_transport::*;

// #[derive(Clone, Debug)]
// pub struct Metrics(metrics::Registry<labels::Key>);
//
// impl Metrics {
//     pub fn new(retain_idle: std::time::Duration) -> (Self, metrics::Report<labels::Key>) {
//         let (reg, report) = metrics::new(retain_idle);
//         (Self(reg), report)
//     }
// }
//
// impl<T: Param<labels::Key>> ExtractParam<Arc<metrics::Metrics>, T> for Metrics {
//     fn extract_param(&self, t: &T) -> Arc<metrics::Metrics> {
//         self.0.metrics(t.param())
//     }
// }

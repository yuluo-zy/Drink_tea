use std::sync::Arc;

pub struct ArcNewService<T, S> {
    inner: Arc<dyn NewService<T, Service = S> + Send + Sync>,
}
pub mod arc_new_service;
pub mod connection;
pub mod new_service;

/// 描述可以产生“T”类型参数的目标
pub trait Param<T> {
    /// Produces a `T`-typed stack paramter.
    fn param(&self) -> T;
}

/// 从 T 类型 产生 P 类型
pub trait ExtractParam<P, T> {
    fn extract_param(&self, t: &T) -> P;
}

/// 一种在“T”类型的目标上设置“P”类型参数的策略，可能会改变目标类型
pub trait InsertParam<P, T> {
    type Target;

    fn insert_param(&self, param: P, target: T) -> Self::Target;
}

/// Implements `ExtractParam` by cloning the inner `P`-typed parameter.
#[derive(Copy, Clone, Debug)]
pub struct CloneParam<P>(P);

/// === ExtractParam ===

impl<F, P, T> ExtractParam<P, T> for F
where
    F: Fn(&T) -> P,
{
    fn extract_param(&self, t: &T) -> P {
        (self)(t)
    }
}

impl<P, T: Param<P>> ExtractParam<P, T> for () {
    fn extract_param(&self, t: &T) -> P {
        t.param()
    }
}

// === impl CloneParam ===

impl<P> From<P> for CloneParam<P> {
    fn from(p: P) -> Self {
        Self(p)
    }
}

/// === InsertParam ===

impl<P, T> InsertParam<P, T> for () {
    type Target = (P, T);

    #[inline]
    fn insert_param(&self, param: P, target: T) -> (P, T) {
        (param, target)
    }
}

impl<F, P, T, U> InsertParam<P, T> for F
where
    F: Fn(P, T) -> U,
{
    type Target = U;

    #[inline]
    fn insert_param(&self, param: P, target: T) -> U {
        (self)(param, target)
    }
}

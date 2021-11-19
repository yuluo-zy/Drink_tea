pub trait Param<T> {
    /// Produces a `T`-typed stack paramter.
    fn param(&self) -> T;
}

/// A strategy for obtaining a `P`-typed parameters from a `T`-typed target.
///
/// This allows stack modules to be decoupled from whether a parameter is known at construction-time
/// or instantiation-time.
pub trait ExtractParam<P, T> {
    fn extract_param(&self, t: &T) -> P;
}

/// A strategy for setting `P`-typed parameters on a `T`-typed target, potentially altering the
/// target type.
pub trait InsertParam<P, T> {
    type Target;

    fn insert_param(&self, param: P, target: T) -> Self::Target;
}

/// Implements `ExtractParam` by cloning the inner `P`-typed parameter.
#[derive(Copy, Clone, Debug)]
pub struct CloneParam<P>(P);

/// === Param ===

/// The identity `Param`.
impl<T: ToOwned> Param<T::Owned> for T {
    #[inline]
    fn param(&self) -> T::Owned {
        self.to_owned()
    }
}

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

impl<P: ToOwned, T> ExtractParam<P::Owned, T> for CloneParam<P> {
    #[inline]
    fn extract_param(&self, _: &T) -> P::Owned {
        self.0.to_owned()
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

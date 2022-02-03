#[derive(Clone, Debug)]
pub struct Stack<S>(S);

pub fn stack<S>(inner: S) -> Stack<S> {
    Stack(inner)
}

impl<S> Stack<S> {
    pub fn push<L>(self, layer: L) -> Stack<L> {
        Stack(layer)
    }
    pub fn into_inner(self) -> S {
        self.0
    }
}

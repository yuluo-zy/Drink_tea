struct Element<T> {
    /// The index of its precedent, **MUST BE VALID AT ANY TIME.**
    prev: usize,
    /// The index of its successor, **MUST BE VALID AT ANY TIME.**
    next: usize,
    data: T,
}

pub struct Window<T> {
    /// Size of the array, must be immutable
    size: usize,
    entry: Vec<Option<Element<T>>>,
    end: Option<usize>,
    len: usize,
}

// This default impl is meant to be used with `std::mem::take` only!
impl<T> Default for Window<T> {
    fn default() -> Self {
        Self::with_size(0)
    }
}

impl<T> Window<T> {
    pub fn with_size(size: usize) -> Self {
        Self {
            size,
            entry: (0..size).map(|_| None).collect(),
            end: None,
            len: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.end.is_none()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        match self.entry[index % self.size].as_mut() {
            Some(elem) => Some(&mut elem.data),
            None => None,
        }
    }

    pub fn push(&mut self, index: usize, data: T) {
        let index = index % self.size;
        if self.entry[index].is_some() {
            return;
        }
        self.entry[index] = Some(match self.end {
            Some(prev) => {
                let prev_elem = self.entry[prev].as_mut().unwrap();
                let next = prev_elem.next;
                prev_elem.next = index;
                self.entry[next].as_mut().unwrap().prev = index;
                Element { prev, next, data }
            }
            #[rustfmt::skip]
            None => Element { prev: index, next: index, data },
        });
        self.end = Some(index);
        self.len += 1;
    }

    pub fn remove(&mut self, index: usize) -> Option<T> {
        let index = index % self.size;
        let elem = self.entry[index].take()?;
        let (prev, next) = (elem.prev, elem.next);
        // self.entry[index] = None;
        self.len -= 1;
        if index == self.end.unwrap() {
            if prev == index {
                self.end = None;
                return Some(elem.data);
            } else {
                self.end = Some(prev);
            }
        }
        self.entry[prev].as_mut().unwrap().next = next;
        self.entry[next].as_mut().unwrap().prev = prev;
        Some(elem.data)
    }

    pub fn contains(&self, index: usize) -> bool {
        self.entry[index].is_some()
    }

    pub fn front(&self) -> Option<&T> {
        self.end.map(|end| {
            let head = self.entry[end].as_ref().unwrap().next;
            &self.entry[head].as_ref().unwrap().data
        })
    }

    pub fn pop_unchecked(&mut self) -> T {
        let end = self.end.unwrap();
        let head = self.entry[end].as_ref().unwrap().next;
        self.remove(head).unwrap()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn for_preceding(&mut self, index: usize, mut action: impl FnMut(&mut T)) {
        let mut index = index % self.size;
        index = match self.entry[index].as_ref() {
            Some(elem) => elem.prev,
            None => return,
        };
        while index != self.end.unwrap() {
            let elem = self.entry[index].as_mut().unwrap();
            action(&mut elem.data);
            index = elem.prev;
        }
    }
}

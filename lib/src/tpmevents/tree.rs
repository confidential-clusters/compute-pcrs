// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
const MAX_EXPECTED_CHILDREN: usize = 2;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct EventNode<T> {
    event: T,
    children: Vec<EventNode<T>>,
    root: bool,
}

impl<T: Clone> EventNode<T> {
    pub fn new(event: T) -> EventNode<T> {
        EventNode {
            event,
            children: Vec::with_capacity(MAX_EXPECTED_CHILDREN),
            root: true,
        }
    }

    pub fn add_child(&mut self, mut child: EventNode<T>) {
        child.root = false;
        self.children.push(child);
    }

    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    pub fn branches(&self) -> Vec<Vec<T>> {
        if self.is_leaf() {
            return vec![vec![self.event.clone()]];
        }

        let mut ret = vec![];
        for child in &self.children {
            for child_branch in &child.branches() {
                let mut branch = vec![self.event.clone()];
                branch.append(&mut child_branch.clone());
                ret.push(branch);
            }
        }

        ret
    }
}

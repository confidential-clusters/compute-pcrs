// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
use super::*;

#[derive(Clone, Debug, PartialEq)]
struct MockEvent {
    pub a: u32,
}

impl PartialEq<u32> for MockEvent {
    fn eq(&self, other: &u32) -> bool {
        self.a == *other
    }
}

static PARENT_DATA: MockEvent = MockEvent { a: 0 };
static CHILD0_DATA: MockEvent = MockEvent { a: 10 };
static CHILD1_DATA: MockEvent = MockEvent { a: 11 };
static CHILD10_DATA: MockEvent = MockEvent { a: 110 };
static CHILD00_DATA: MockEvent = MockEvent { a: 100 };
static CHILD01_DATA: MockEvent = MockEvent { a: 101 };
static CHILD000_DATA: MockEvent = MockEvent { a: 1000 };

fn build_example() -> EventNode<MockEvent> {
    // Define data/nodes
    let mut root = EventNode::<MockEvent>::new(PARENT_DATA.clone());
    let mut child0 = EventNode::<MockEvent>::new(CHILD0_DATA.clone());
    let mut child1 = EventNode::<MockEvent>::new(CHILD1_DATA.clone());
    let child10 = EventNode::<MockEvent>::new(CHILD10_DATA.clone());
    let mut child00 = EventNode::<MockEvent>::new(CHILD00_DATA.clone());
    let child01 = EventNode::<MockEvent>::new(CHILD01_DATA.clone());
    let child000 = EventNode::<MockEvent>::new(CHILD000_DATA.clone());
    // Build the tree
    child00.add_child(child000);
    child0.add_child(child00);
    child0.add_child(child01);
    child1.add_child(child10);
    root.add_child(child0);
    root.add_child(child1);
    root
}

#[test]
fn test_create() {
    let mock = MockEvent { a: 123 };
    let node = EventNode::<MockEvent>::new(mock.clone());
    assert_eq!(node.children.len(), 0);
    assert_eq!(node.event, mock);
}

#[test]
fn test_add_child() {
    let root_data = MockEvent { a: 0 };
    let mut root = EventNode::<MockEvent>::new(root_data.clone());
    let child_data = MockEvent { a: 11111 };
    let child = EventNode::<MockEvent>::new(child_data.clone());
    root.add_child(child);
    assert_eq!(root.children.len(), 1);
    assert_eq!(root.event, root_data);
    assert_eq!(root.children[0].event, child_data);
}

#[test]
fn test_add_children() {
    let root = build_example();
    // Check the tree
    assert_eq!(root.children.len(), 2);
    assert_eq!(root.event, PARENT_DATA);
    assert_eq!(root.children[0].event, CHILD0_DATA);
    assert_eq!(root.children[1].event, CHILD1_DATA);
    assert_eq!(root.children[0].children.len(), 2);
    assert_eq!(root.children[1].children.len(), 1);
    assert_eq!(root.children[0].children[0].event, CHILD00_DATA);
    assert_eq!(root.children[0].children[0].children.len(), 1);
    assert_eq!(root.children[0].children[1].event, CHILD01_DATA);
    assert_eq!(root.children[0].children[1].children.len(), 0);
    assert_eq!(
        root.children[0].children[0].children[0].event,
        CHILD000_DATA
    );
    assert_eq!(root.children[0].children[0].children[0].children.len(), 0);
}

#[test]
fn test_leafs() {
    let root = build_example();
    assert!(!root.is_leaf());
    assert!(!root.children[0].is_leaf());
    assert!(!root.children[1].is_leaf());
    assert!(!root.children[0].children[0].is_leaf());
    assert!(root.children[0].children[1].is_leaf());
    assert!(root.children[0].children[0].children[0].is_leaf());
}

#[test]
fn test_branches_tree() {
    let root = build_example();
    let branches = root.branches();
    assert_eq!(
        branches,
        vec![vec![0, 10, 100, 1000], vec![0, 10, 101], vec![0, 11, 110],]
    );
}

#[test]
fn test_branches_node() {
    let mock = MockEvent { a: 123 };
    let node = EventNode::<MockEvent>::new(mock.clone());
    assert_eq!(node.branches(), vec![vec![123]]);
}

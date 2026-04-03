// MIT License
// Copyright (c) 2024 quantix

// Q8 smoke tests for hashtree package
// Covers: HashTreeNode, HashTree.Build, BuildHashTree, NewHashTree
package hashtree

import (
	"testing"
)

func TestNewHashTree_Build_NonEmpty(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
		[]byte("leaf4"),
	}
	tree := NewHashTree(leaves)
	if err := tree.Build(); err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}
	if tree.Root == nil {
		t.Fatal("expected non-nil root after Build")
	}
	if tree.Root.Hash == nil {
		t.Fatal("expected non-nil root hash")
	}
}

func TestNewHashTree_SingleLeaf(t *testing.T) {
	tree := NewHashTree([][]byte{[]byte("solo")})
	if err := tree.Build(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Root == nil {
		t.Fatal("nil root for single-leaf tree")
	}
}

func TestBuildHashTree_Deterministic(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	root1 := BuildHashTree(leaves)
	root2 := BuildHashTree(leaves)
	if root1.Hash.Cmp(root2.Hash) != 0 {
		t.Errorf("root hash not deterministic: %v != %v", root1.Hash, root2.Hash)
	}
}

func TestBuildHashTree_DifferentLeavesProduceDifferentRoot(t *testing.T) {
	r1 := BuildHashTree([][]byte{[]byte("hello")})
	r2 := BuildHashTree([][]byte{[]byte("world")})
	if r1.Hash.Cmp(r2.Hash) == 0 {
		t.Error("different leaves produced same root hash")
	}
}

func TestBuildHashTree_OddLeaves(t *testing.T) {
	// Odd number of leaves — last node is carried over, no panic
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")}
	root := BuildHashTree(leaves)
	if root == nil || root.Hash == nil {
		t.Fatal("nil root or hash with odd-count leaves")
	}
}

func TestHashTreeNode_GetSiblingNode(t *testing.T) {
	left := &HashTreeNode{}
	right := &HashTreeNode{}
	parent := &HashTreeNode{Left: left, Right: right}

	sib, err := parent.GetSiblingNode(0) // even index → right child
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sib != right {
		t.Error("expected right sibling for even index")
	}

	sib, err = parent.GetSiblingNode(1) // odd index → left child
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sib != left {
		t.Error("expected left sibling for odd index")
	}
}

func TestHashTreeNode_GetSiblingNode_NoSibling(t *testing.T) {
	leaf := &HashTreeNode{} // no children
	_, err := leaf.GetSiblingNode(0)
	if err == nil {
		t.Error("expected error for leaf node without children")
	}
}

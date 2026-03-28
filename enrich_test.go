package main

import "testing"

func TestBlastRadius(t *testing.T) {
	// A -> B -> C ; edges: dependent -> dependency
	links := []GraphLink{
		{Source: "A", Target: "B"},
		{Source: "B", Target: "C"},
	}
	rev := reverseDependents(links)
	if blastRadius("C", rev) != 2 {
		t.Fatalf("C blast radius: got %d want 2", blastRadius("C", rev))
	}
	if blastRadius("B", rev) != 1 {
		t.Fatalf("B blast radius: got %d want 1", blastRadius("B", rev))
	}
}

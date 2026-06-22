package main

import "testing"

// TestVersionDefault is a build-smoke test: it ensures the binary's package
// compiles and the default version sentinel is in place.
func TestVersionDefault(t *testing.T) {
	if version == "" {
		t.Fatal("version must have a non-empty default")
	}
}

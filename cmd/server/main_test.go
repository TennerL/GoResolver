package main

import (
	"math"
	"testing"
)

func TestSOASerialFromUnixZeroFallsBackToOne(t *testing.T) {
	if got := soaSerialFromUnix(0); got != 1 {
		t.Fatalf("expected serial 1, got %d", got)
	}
}

func TestSOASerialFromUnixClampsUint32(t *testing.T) {
	if got := soaSerialFromUnix(math.MaxInt64); got != math.MaxUint32 {
		t.Fatalf("expected serial %d, got %d", uint32(math.MaxUint32), got)
	}
}

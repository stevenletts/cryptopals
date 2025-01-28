package xor

import (
	"testing"
)

func TestHammingDistanceForStrings(t *testing.T) {
	res := hammingDistanceForStrings("this is a test", "wokka wokka!!!")

	if res != 37 {
		t.Fatalf("failed to calculate the correct hamming distance for 2 strings. Expected: 37, Got: %d", res)
	}
}

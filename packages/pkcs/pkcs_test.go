package pkcs

import (
	"bytes"
	"testing"
)

func TestPkcs7Pad(t *testing.T) {
	var inp = "YELLOW SUBMARINE"
	var expected = []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	res := Pkcs7Pad([]byte(inp), 20)

	if bytes.Compare(res, expected) != 0 {
		t.Fatalf("failed to pad the input")
	}
}

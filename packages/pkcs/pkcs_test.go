package pkcs

import (
	"bytes"
	"testing"
)

func TestPkcs7Pad(t *testing.T) {
	var inp = "YELLOW SUBMARINE"
	var expected = []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	res := Pad7([]byte(inp), 20)

	if bytes.Compare(res, expected) != 0 {
		t.Fatalf("failed to pad the input")
	}
}

func TestHasPad7(t *testing.T) {
    tests := []struct {
        name       string
        input      string
        wantPadded bool
        wantLen    int
    }{
        {
            name:       "Valid padding",
            input:      "ICE ICE BABY\x04\x04\x04\x04",
            wantPadded: true,
            wantLen:    4,
        },
        {
            name:       "Invalid padding",
            input:      "ICE ICE BABY\x05\x05\x05\x05",
            wantPadded: false,
            wantLen:    0,
        },
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            gotPadded, gotLen := HasPad7([]byte(tc.input))
            if gotPadded != tc.wantPadded {
                t.Errorf("HasPad7(%q) = padded %v; want %v", tc.input, gotPadded, tc.wantPadded)
            }
            if gotLen != tc.wantLen {
                t.Errorf("HasPad7(%q) = length %d; want %d", tc.input, gotLen, tc.wantLen)
            }
        })
    }
}

package ecb

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestDecryptAes128Ecb(t *testing.T) {
	data, _ := os.ReadFile("./test_files/aes_encrypted_file.txt")
	decoded, _ := base64.StdEncoding.DecodeString(string(data))
	txt, err := DecryptAes128Ecb(decoded, []byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatalf("TestDecryptAes128Ecb failed to decrypt")
	}

	var expected = "I'm back and I'm ringin' the bell"
	if strings.Compare(string(txt[:33]), expected) != 0 {
		t.Fatalf("txt[:33] did not match ")
	}
}

func TestCheckFileForECBSuccess(t *testing.T) {
	line := CheckFileForECB("./test_files/find_ECB_line.txt")

	if line != 133 {
		t.Fatalf("File ECB check failed. expected: 133, got: %d", line)
	}
}

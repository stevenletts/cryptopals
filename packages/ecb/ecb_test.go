package ecb

import (
	"encoding/base64"
	//	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDecryptAesEcb(t *testing.T) {
	data, _ := os.ReadFile("./test_files/aes_encrypted_file.txt")
	decoded, _ := base64.StdEncoding.DecodeString(string(data))
	txt, err := DecryptAesEcb(decoded, []byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatalf("TestDecryptAesEcb failed to decrypt")
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

func TestEncryptAesCbc(t *testing.T) {
	var key = []byte("YELLOW SUBMARINE")
	var plaintext = []byte("abcdefghijklmnop")
	iv := make([]byte, 16)

	ciphertext, err := EncryptAesCbc(plaintext, iv, key)

	if err != nil {
		t.Fatalf("something went wrong")
	}

	fmt.Printf("\nciphertext:\n%+v\n", string(ciphertext))

	plaintext2, _ := DecryptAesCbc(ciphertext, iv, key)

	fmt.Printf("\nplaintext:\n%+v\n", string(plaintext2))
}

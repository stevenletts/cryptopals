package ecb

import (
	"bytes"
	"encoding/base64"
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

func TestEncryptAesCbcSimple(t *testing.T) {
	var key = []byte("YELLOW SUBMARINE")
	var plaintext = []byte("abcdefghijklmnop")
	iv := make([]byte, 16)

	ciphertext, err := EncryptAesCbc(plaintext, iv, key)

	if err != nil {
		t.Fatalf("something went wrong")
	}

	plaintext2, _ := DecryptAesCbc(ciphertext, iv, key)
	res := bytes.Trim(plaintext2, "\x00")

	if bytes.Compare(res, plaintext) != 0 {
		t.Fatalf("failed the cbc envryopt decrypt flow. expected %s, recieved %s", string(plaintext), string(plaintext2))
	}

}

func TestEncryptAesCbcExample(t *testing.T) {
	var key = []byte("YELLOW SUBMARINE")
	iv := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	data, _ := os.ReadFile("./test_files/cbc_encrypted.txt")

	decoded, _ := base64.StdEncoding.DecodeString(string(data))
	plaintext, _ := DecryptAesCbc(decoded, iv, key)

	res := bytes.Trim(plaintext, "\x00")

	if strings.Compare(string(res[:33]), "I'm back and I'm ringin' the bell") != 0 {
		t.Fatalf("failed to decode the cbc file")
	}

}

package pkcs

import (
	"bytes"
)

// Pkcs7Pad takes a input text in byte form and a desired block size and pads the difference of the inp byte slice and the block size with
// the byte that is equal to the difference
func Pkcs7Pad(plaintext []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(plaintext) % blockSize)
	padByte := byte(paddingLen)
	padding := bytes.Repeat([]byte{padByte}, paddingLen)

	return append(plaintext, padding...)
}

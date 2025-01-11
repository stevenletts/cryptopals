package pkcs

import (
	"bytes"
)

// Pad7 takes a input text in byte form and a desired block size and pads the difference of the inp byte slice and the block size with
// the byte that is equal to the difference
func Pad7(plaintext []byte, blockSize int) []byte {
	toPad := len(plaintext) % blockSize

	if toPad == 0 {
		return plaintext
	}

	paddingLen := blockSize - toPad

	padByte := byte(paddingLen)
	padding := bytes.Repeat([]byte{padByte}, paddingLen)

	return append(plaintext, padding...)
}

func Pad7Remove(data []byte, blockSize int) []byte {
	paddingLen := int(data[len(data)-1])
	return data[:len(data) - paddingLen]
}
package pkcs

import (
	"bytes"
	"errors"
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

// HasPad7 will return if an input has padding (and it is valid) and if so the length
func HasPad7(data []byte) (bool, int) {
	last := data[len(data)-1]
	length := int(last)

	for i := len(data) -1; i >= len(data) -length; i-- {
		b := data[i]
		if b == last {
			continue
		}
		return false, 0
	}

	return true, length
}

func StripPad7(data []byte, length int) ([]byte, error) {
	if has, l := HasPad7(data); has {
		return data[:len(data)-l], nil
	}

	return data, errors.New("is not pad7")
}
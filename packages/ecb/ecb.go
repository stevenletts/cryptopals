package ecb

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"os"
	"slices"
)

// DecryptAes128Ecb talkes a data and key byte slice and applies the cipher in blocks of 16
// in the decryption
func DecryptAes128Ecb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(data))
	for i, j := 0, 16; i < len(data); i, j = i+16, j+16 {
		cipher.Decrypt(plainText[i:j], data[i:j])
	}
	return plainText, nil
}

func CheckFileForECB(fp string) int {
	file, err := os.Open(fp)

	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(file)

	var counter int = 1

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		clean := bytes.TrimRight(line, "\r\n")

		var chunks [][]byte

		for i, j := 0, 16; j < len(clean); i, j = i+16, j+16 {
			chunks = append(chunks, clean[i:j])
		}

		// for each chunk if the chunk is in the remaining items then we have a match
		var found = false
		for i, v := range chunks {
			for j, s := range chunks {
				// ignore same index elements
				if i == j {
					continue
				}

				if slices.Equal(v, s) {
					found = true
					break
				}

			}
			if found {
				break
			}
		}
		if found {
			break
		}

		counter += 1
	}

	return counter
}

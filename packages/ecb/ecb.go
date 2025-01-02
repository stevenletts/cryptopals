package ecb

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"github.com/stevenletts/cryptopals/packages/pkcs"
	"github.com/stevenletts/cryptopals/packages/xor"
	"os"
	"slices"
)

// ChunkByteSlice takes a data src and a blocksize and returns a slice of equal chunks with padding at the end if required
func ChunkByteSlice(data []byte, size int) [][]byte {
	var ret [][]byte
	// there is an early retrun if pad len is 0 which i assume to be true for cipherd text for now at least
	padded := pkcs.Pad7(data, size)
	for i := 0; i < len(padded); i += size {
		ret = append(ret, padded[i:i+size])
	}

	return ret
}

// DecryptAesEcb talkes a data and key byte slice and applies the cipher in blocks of 16
// in the decryption
func DecryptAesEcb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(data))
	size := cipher.BlockSize()
	chunks := ChunkByteSlice(data, size)

	for i, chunk := range chunks {
		var from, to int = i * size, (i + 1) * size
		cipher.Decrypt(plainText[from:to], chunk)
	}

	return plainText, nil
}

func EncryptAesEcb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(data))
	size := cipher.BlockSize()
	chunks := ChunkByteSlice(data, size)

	for i, chunk := range chunks {
		var from, to int = i * size, (i + 1) * size
		cipher.Encrypt(plainText[from:to], chunk)
	}

	return plainText, nil
}

func EncryptAesCbc(plaintext, iv, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := cipher.BlockSize()
	ciphertext := make([]byte, len(plaintext))

	chunks := ChunkByteSlice(plaintext, size)
	prev := iv
	for i, chunk := range chunks {
		var from, to int = i * size, (i + 1) * size
		xord, err := xor.ApplyXor(chunk, prev)

		if err != nil {
			panic(err)
		}

		cipher.Encrypt(ciphertext[from:to], xord)
		prev = ciphertext[from:to]
	}

	return ciphertext, nil
}

func DecryptAesCbc(ciphertext, iv, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := cipher.BlockSize()
	plaintext := make([]byte, len(ciphertext))
	chunks := ChunkByteSlice(ciphertext, size)

	prev := iv
	for i, chunk := range chunks {
		var from, to int = i * size, (i + 1) * size
		xord, err := xor.ApplyXor(chunk, prev)

		if err != nil {
			panic(err)
		}

		cipher.Decrypt(plaintext[from:to], xord)
		prev = ciphertext[from:to]
	}

	return plaintext, nil
}

func EncryptAesEcbInCbcMode(plaintext, iv, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	for i, j := 0, 16; i < len(ciphertext); i, j = i+16, j+16 {
		var prev []byte
		if i == 0 {
			prev = iv
		} else {
			prev = ciphertext[i-16 : j-16]
		}
		cipher.Encrypt(ciphertext[i:j], prev)
	}
	return ciphertext, nil
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

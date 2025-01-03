package ecb

import (
	"crypto/rand"
	"errors"
	randmath "math/rand/v2"
	"slices"
)

// generateRandByteSlice takes a length and generates a byte slice with a random sequence of bytes
func generateRandByteSlice(l int) []byte {
	b := make([]byte, l)
	_, err := rand.Read(b)

	if err != nil {
		panic(err)
	}

	return b
}

// this is a wrapper for challenge 11
func encryptionOracle(plaintext []byte) ([]byte, int) {
	prependSlice := generateRandByteSlice(randmath.IntN(5) + 5)
	appendSlice := generateRandByteSlice(randmath.IntN(5) + 5)

	modifiedPlaintext := append(prependSlice, plaintext...)
	modifiedPlaintext = append(modifiedPlaintext, appendSlice...)

	key := generateRandByteSlice(16)

	var ciphertext []byte
	var err error
	var encryptionMode int = randmath.IntN(2)

	switch encryptionMode {
	case 0:
		ciphertext, err = EncryptAesEcb(modifiedPlaintext, key)

		if err != nil {
			panic(err)
		}

	case 1:
		iv := generateRandByteSlice(16)
		ciphertext, err = EncryptAesCbc(modifiedPlaintext, iv, key)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.New("this should not happen"))
	}

	return ciphertext, encryptionMode
}

func checkChunksForECB(chunks [][]byte) bool {
	for i, c := range chunks {
		for j, c2 := range chunks {
			if i == j {
				continue
			}

			if slices.Equal(c, c2) {
				return true
			}
		}
	}
	return false
}

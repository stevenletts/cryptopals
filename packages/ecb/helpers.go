package ecb

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	"errors"
	"fmt"
	randmath "math/rand/v2"
	"os"
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


// fillByteSlice just fills a byte slice with a A byte to the length of the slice.
func fillByteSlice(toFill []byte) []byte {
	for p := 0; p < len(toFill); p++ {
		toFill[p] = byte('A')
	}
	return toFill
}

func discoverBlockSize(encryptor encryptionFunc) int {
	var previousLen = 0
	var i = 1

	for {
		testText := fillByteSlice(make([]byte, i))
		ct := encryptor(testText)
		ctLen := len(ct)

		if previousLen == 0 {
			previousLen = ctLen
		}

		if previousLen < ctLen {
			return ctLen - previousLen
		}

		i++
	}
}


func checkChunksForECB[T comparable](chunks [][]T) bool {
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



type encryptionFunc func([]byte) []byte

func makeSecretEncryptionFn() encryptionFunc {
	data, err := os.ReadFile("./test_files/secret64.txt")

	if err != nil {
		panic(err)
	}

	secret, _ := base64.StdEncoding.DecodeString(string(data))
	var key []byte = generateRandByteSlice(16)

	encryptionFn := func(plaintext []byte) []byte {
		var fulltext []byte = append(plaintext, secret...)

		ciphertext, err := EncryptAesEcb(fulltext, key)

		if err != nil {
			panic(err)
		}

		return ciphertext
	}

	return encryptionFn
}


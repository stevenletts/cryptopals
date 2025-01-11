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

// this is a wrapper for challenge 11
func encryptionOracle(plaintext []byte) ([]byte, string) {
	prependSlice := generateRandByteSlice(randmath.IntN(5) + 5)
	appendSlice := generateRandByteSlice(randmath.IntN(5) + 5)

	modifiedPlaintext := append(prependSlice, plaintext...)
	modifiedPlaintext = append(modifiedPlaintext, appendSlice...)

	key := generateRandByteSlice(16)

	var ciphertext []byte
	var err error
	var encryptionModeRand int = randmath.IntN(2)
	var mode string

	switch encryptionModeRand {
	case 0:
		mode = "ECB"
		ciphertext, err = EncryptAesEcb(modifiedPlaintext, key)

		if err != nil {
			panic(err)
		}

	case 1:
		mode = "CBC"
		iv := generateRandByteSlice(16)
		ciphertext, err = EncryptAesCbc(modifiedPlaintext, iv, key)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.New("this should not happen"))
	}

	return ciphertext, mode
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

type StringKVParser map[string]string

func (s StringKVParser) Get(key string) (string, bool) {
	val, ok := s[key]
	return val, ok
}

func (s StringKVParser) Set(key, value string) {
	s[key] = value
}

func keyValueParser(str string) StringKVParser {
	parser := StringKVParser{}

	kvs := strings.Split(str, "&")

	for _, kvPair := range kvs {
		parts := strings.Split(kvPair, "=")
		if len(parts) == 2 {
			k, v := parts[0], parts[1]
			parser.Set(k, v)
		} else {
			panic(errors.New("check why the kvPair is outputting multiple parts"))
		}
	}

	return parser
}

func profileFor(email string) string {
    // Sanitizing the email by removing '&' and '='
    sanitizedEmail := strings.NewReplacer("&", "", "=", "").Replace(email)

    // Build in the desired order explicitly:
    kvPairs := []string{
        fmt.Sprintf("email=%s", sanitizedEmail),
        fmt.Sprintf("uid=%s", "10"),
        fmt.Sprintf("role=%s", "user"),
    }

    return strings.Join(kvPairs, "&")
}
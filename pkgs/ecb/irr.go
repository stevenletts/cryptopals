package ecb

import (
	"errors"
	"fmt"
	randmath "math/rand/v2"
	"strings"
)

// the below are all related to a specific challenges to explore a specific concept. They aren't exactly useful
// to the modules themselves so stashing them here because they can be useful to re-explore concepts

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

// this is a wrapper for challenge 11 it either encryptes using aes or ecb using a random key
// and returns the mode and the ciphertext.
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

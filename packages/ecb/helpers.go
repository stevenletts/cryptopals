package ecb

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
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

func makeSecretEncryptionFn(includeFixedRandomPrefix bool) encryptionFunc {
	data, err := os.ReadFile("./test_files/secret64.txt")

	if err != nil {
		panic(err)
	}

	secret, _ := base64.StdEncoding.DecodeString(string(data))
	var key = generateRandByteSlice(16)
	var randomFixedPrefix []byte

	if includeFixedRandomPrefix {
		randLength := randmath.IntN(100)

		randomFixedPrefix = generateRandByteSlice(randLength)
	}

	encryptionFn := func(plaintext []byte) []byte {

		var fulltext = append(plaintext, secret...)
		var fullTextWithPrefix = append(randomFixedPrefix, fulltext...)

		ciphertext, err := EncryptAesEcb(fullTextWithPrefix, key)

		if err != nil {
			panic(err)
		}

		return ciphertext
	}

	return encryptionFn
}

func findRandomPrefixLen(enc encryptionFunc, blockSize int) int {
	// first find the not furthest not changing block from an input of 1

	noInp := enc([]byte{})
	singleByte := enc([]byte{'A'})

	noInpChunks, _ := ChunkByteSlice(noInp, blockSize)
	singleChunks, _ := ChunkByteSlice(singleByte, blockSize)

	// the ith chunk that has changed is the one that our attack bytes are hitting. everything before or after should be the same. i.e the prefix length ends in ithChunkChanged
	// so then its a question of where in that chunk
	var ithChunkChanged int

	// find last changed chunk
	for i, noInpChunk := range noInpChunks {
		if bytes.Compare(noInpChunk, singleChunks[i]) != 0 {
			ithChunkChanged = i
			break
		}
	}

	// to find the remainder of the chunk save the previous iteration chunk and rerun then add a single byte. this push everything down one so every chunk following
	//the byte will be different. to isolate the remainder a comparison against the previous ithchunk (known entry point of the attack input) of the next iteration
	// and if it does not change then we have filled the slice. this actually happens in the previous iteration so we minus one to get the actual prefix length.
	var prevjthchunk []byte
	var extraLen int
	var result int

	for j := 0; j < blockSize; j++ {
		checkingChunks, _ := ChunkByteSlice(enc(make([]byte, j)), blockSize)

		if prevjthchunk == nil || len(prevjthchunk) == 0 {
			prevjthchunk = checkingChunks[ithChunkChanged]
			continue
		}

		if bytes.Compare(prevjthchunk, checkingChunks[ithChunkChanged]) == 0 {
			// its actually the previous iteration that filled the chunk but we see the confirmed result in the +1.
			extraLen = j -1
			break
		}

		prevjthchunk = checkingChunks[ithChunkChanged]
	}

	// off by one lol
	result = (blockSize * (ithChunkChanged + 1)) - extraLen

	return result
}

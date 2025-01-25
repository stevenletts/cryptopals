package ecb

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"errors"

	"github.com/stevenletts/cryptopals/packages/pkcs"
	"github.com/stevenletts/cryptopals/packages/xor"
	"os"
)

// ChunkByteSlice takes a data src and a blocksize and returns a slice of equal chunks with padding at the end if required
func ChunkByteSlice(data []byte, size int) ([][]byte, int) {
	var ret [][]byte
	var length = 0
	// there is an early retrun if pad len is 0 which i assume to be true for cipherd text for now at least

	padded := pkcs.Pad7(data, size)

	for i := 0; i < len(padded); i += size {
		length += size
		ret = append(ret, padded[i:i+size])
	}

	return ret, length
}

// DecryptAesEcb takes a data and key byte slice and applies the cipher in blocks of 16
// in the decryption
func DecryptAesEcb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	size := cipher.BlockSize()
	chunks, length := ChunkByteSlice(data, size)
	plainText := make([]byte, length)

	for i, chunk := range chunks {
		var from, to = i * size, (i + 1) * size
		cipher.Decrypt(plainText[from:to], chunk)
	}

	return plainText, nil
}

func EncryptAesEcb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	size := cipher.BlockSize()
	chunks, length := ChunkByteSlice(data, size)
	plainText := make([]byte, length)

	for i, chunk := range chunks {
		var from, to = i * size, (i + 1) * size
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

	chunks, length := ChunkByteSlice(plaintext, size)
	ciphertext := make([]byte, length)

	prev := iv
	for i, chunk := range chunks {
		var from, to = i * size, (i + 1) * size
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
	chunks, length := ChunkByteSlice(ciphertext, size)
	plaintext := make([]byte, length)

	prev := iv
	for _, chunk := range chunks {
		dec := make([]byte, size)
		cipher.Decrypt(dec, chunk)

		xord, err := xor.ApplyXor(dec, prev)

		if err != nil {
			panic(err)
		}

		plaintext = append(plaintext, xord...)

		prev = chunk
	}

	return plaintext, nil
}

func CheckFileForECB(fp string) int {
	file, err := os.Open(fp)

	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(file)

	var counter = 1
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		clean := bytes.TrimRight(line, "\r\n")

		var chunks [][]byte
		chunks, _ = ChunkByteSlice(clean, 16)

		var ecbFound = checkChunksForECB(chunks)

		if ecbFound {
			break
		}

		counter += 1
	}

	return counter
}

// DetectECBOrCBC takes a string to pass to a helper fn for the challenge and then returns true if a mode was detected and the mode found
// otherwise false and the mode that the helper used
func DetectECBOrCBC(atk []byte) (bool, string) {
	ciphertext, encryptionMode := encryptionOracle(atk)
	chunks, _ := ChunkByteSlice(ciphertext, 16)

	var ecbFound = checkChunksForECB(chunks)

	if encryptionMode == "ECB" && ecbFound {
		return true, encryptionMode
	} else if encryptionMode == "CBC" && !ecbFound {
		return true, encryptionMode
	}

	return false, encryptionMode
}

func getCipherTextsChunksForPrefixTransposed(size int, enc encryptionFunc) [][][]byte {
	var ciphertexts [][][]byte

	// first create all possible ciphertexts with the possible chunk size variable
	// we use -1 because it means the last cipher text is no prefix instead of the first in the slice so when transposed its easier
	for i := size - 1; i > -1; i-- {
		ciphertext := enc(fillByteSlice(make([]byte, i)))
		chunks, _ := ChunkByteSlice(ciphertext, size)
		ciphertexts = append(ciphertexts, chunks)
	}

	// group all the input chunks together so its like [[[c1-15],[c1-14],[c1-13]],[[c2-15],[c2-14],[c3-13]]]
	// using size means we can end up with empty slices with no ciphertext but thats ok because the iterators should handle skipping
	// as there could always be a max of size to be filled.
	transposed := make([][][]byte, size)
	for i := 0; i < size; i++ {
		var group [][]byte
		for _, ciphertext := range ciphertexts {
			if i < len(ciphertext) {
				chunk := ciphertext[i]
				group = append(group, chunk)
			}
		}
		transposed[i] = group
	}

	return transposed
}

func ByteAtATimeECBDecryption(enc encryptionFunc) []byte {
	blockSize := discoverBlockSize(enc)

		chunks, _ := ChunkByteSlice(enc(fillByteSlice(make([]byte, blockSize*2))), blockSize)
		isEcb := checkChunksForECB(chunks)

	    // not really possible here but the challenge called for it.
		if !isEcb {
			panic(errors.New("the encryption is not ECB"))
		}

	ctsTransposed := getCipherTextsChunksForPrefixTransposed(blockSize, enc)

	var plaintext []byte = fillByteSlice(make([]byte, blockSize-1))
	for i := 0; i < len(ctsTransposed); i++ {
		transposedChunksSolvingFor := ctsTransposed[i]
		for j := 0; j < len(transposedChunksSolvingFor); j++ {
			chunkToSolveFor := transposedChunksSolvingFor[j]
			// the last 15 works like a sliding window to capture the latest solved bytes and always feed in a chunk
			// that is one byte short of a known input to match against the solve for
			last15 := plaintext[len(plaintext)-15:]

			for k := 0; k < 256; k++ {
				sliceToSolveFor := append(last15, byte(k))
				x := enc(sliceToSolveFor)[:blockSize]

				if bytes.Compare(x, chunkToSolveFor) == 0 {
					plaintext = append(plaintext, byte(k))
					break
				}
			}

		}
	}

	return plaintext[blockSize-1:]
}

func ByteAtATimeECBDecryptionWithRandomPrefix() []byte {
	enc := makeSecretEncryptionFn(true)
	blockSize := discoverBlockSize(enc)

	prefixLen := findRandomPrefixLen(enc, blockSize)
	space := blockSize - (prefixLen % blockSize)
	roundedUp := (prefixLen + blockSize - 1) / blockSize

	// wrap the enc fn to amend the input to always have the dist between a full block and the prefix so that we are only seeing plaintext
	// then drop the prefix bytes so its a "clean" input of the attack+enc value
	wrappedEnc := func(inp []byte) []byte {
		amendedInp := append(make([]byte, space), inp...)
		res := enc(amendedInp)
		return res[roundedUp*blockSize:]
	}


	return ByteAtATimeECBDecryption(wrappedEnc)
}

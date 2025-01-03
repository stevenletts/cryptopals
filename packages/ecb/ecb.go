package ecb

import (
	"bufio"
	"bytes"
	"crypto/aes"
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
	size := cipher.BlockSize()
	chunks, length := ChunkByteSlice(data, size)
	plainText := make([]byte, length)

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

	chunks, length := ChunkByteSlice(plaintext, size)
	ciphertext := make([]byte, length)

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

	var counter int = 1
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		clean := bytes.TrimRight(line, "\r\n")

		var chunks [][]byte
		chunks, _ = ChunkByteSlice(clean, 16)

		var ecbFound bool = checkChunksForECB(chunks)

		if ecbFound {
			break
		}

		counter += 1
	}

	return counter
}

func DetectECBOrCBC(atk []byte) bool {
	ciphertext, encryptionMode := encryptionOracle(atk)
	chunks, _ := ChunkByteSlice(ciphertext, 16)

	var ecbFound bool = checkChunksForECB(chunks)

	if encryptionMode == 0 && ecbFound {
		return true
	} else if encryptionMode == 1 && !ecbFound {
		return true
	}

	return false
}

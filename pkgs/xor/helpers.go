package xor

import (
	"errors"
	"math/bits"
)

type fillKey struct {
	length int
	char   byte
}
type KeysizeEvaluation struct {
	Keysize int
	Score   float64
}

var makeAndFillCache = map[fillKey][]byte{}

func hammingDistance(b1, b2 []byte) int {
	xord, err := ApplyXor(b1, b2)

	if err != nil {
		panic(errors.New("error applying xor in hamming distance calculation"))
	}
	var res int

	for _, v := range xord {
		res += bits.OnesCount8(v)
	}

	return res
}

func hammingDistanceForStrings(s1, s2 string) int {
	b1 := []byte(s1)
	b2 := []byte(s2)

	return hammingDistance(b1, b2)
}

// transposeBlocks takes a pointer to a sequence of bytes and iterates over them creating slices stored in a map where i..keysize: bytes in ith position
func transposeBlocks(d *[]byte, keysize int) [][]byte {
	ret := make([][]byte, keysize)

	for i, v := range *d {
		ret[i%keysize] = append(ret[i%keysize], v)
	}

	return ret
}

func evalutatePlainText(bs []byte) int {
	var ret = 0
	for _, b := range bs {
		ret += getCharWeight(b)
	}
	return ret
}

func repeatingKeyXor(ciphertext, key []byte) []byte {
	plaintext := make([]byte, len(ciphertext))
	for i, c := range ciphertext {
		plaintext[i] = c ^ key[i%len(key)]
	}
	return plaintext
}

// getCharWeight simple character weighting system. uses ETAOIN SHRDLU as the scoring mechanism and returns a score.
func getCharWeight(char byte) int {
	wm := map[byte]int{
		byte('U'): 2,
		byte('u'): 2,
		byte('L'): 3,
		byte('l'): 3,
		byte('D'): 4,
		byte('d'): 4,
		byte('R'): 5,
		byte('r'): 5,
		byte('H'): 6,
		byte('h'): 6,
		byte('S'): 7,
		byte('s'): 7,
		byte(' '): 8,
		byte('N'): 9,
		byte('n'): 9,
		byte('I'): 10,
		byte('i'): 10,
		byte('O'): 11,
		byte('o'): 11,
		byte('A'): 12,
		byte('a'): 12,
		byte('T'): 13,
		byte('t'): 13,
		byte('E'): 14,
		byte('e'): 14,
	}
	return wm[char]
}

// makeAndFill creates a slice of length l filled with a specific byte b and caches them so they are available for reuse if attempting to iterate a high
// number of solutions.
func makeAndFill(l int, c byte) []byte {
	key := fillKey{
		l,
		c,
	}
	v, ok := makeAndFillCache[key]
	if ok {
		return v
	}

	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = c
	}
	makeAndFillCache[key] = ret

	return ret
}

func xorByte(b1, b2 byte) byte {
	return b1 ^ b2
}

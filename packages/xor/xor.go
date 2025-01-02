package xor

import (
	"bufio"
	"encoding/hex"
	"errors"
	"os"
	"sort"
)

// ApplyXor xor takes two equal length byte slices and returns the exclusive or
// from the bitwise operator on each elemenent sequentially
func ApplyXor(s1, s2 []byte) ([]byte, error) {
	if len(s1) != len(s2) {
		return nil, errors.New("length mismatch in xor")
	}

	res := make([]byte, len(s1))

	for i := 0; i < len(res); i++ {
		res[i] = xorByte(s1[i], s2[i])
	}

	return res, nil
}

// FindSingleByteXor takes bytes that should be decoded and then xors against every character possible to check for single byte encryption
// returns the unencoded sequence, the score and the byte used to decoded
func FindSingleByteXor(inp []byte) ([]byte, int, byte) {
	var answer []byte
	var score = 0
	var key byte
	length := len(inp)

	for i := 0; i < 256; i++ {
		temp := makeAndFill(length, byte(i))
		res, err := ApplyXor(inp, temp)
		localScore := 0

		if err != nil {
			panic("no idea why this happened")
		}

		for _, v := range res {
			val := getCharWeight(v)
			localScore += val
		}

		if localScore > score {
			answer = res
			score = localScore
			key = byte(i)
		}
	}

	return answer, score, key
}

// FindSingleXordLineInFile probably can remove this it just reads a file and iterates using the main fn - leaving as it is
// part of challenge 4 though
func FindSingleXordLineInFile(fp string) []byte {
	file, err := os.Open(fp)

	if err != nil {
		panic(err)
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	reader := bufio.NewReader(file)

	var answer []byte
	var score = 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		decodedHex, _ := hex.DecodeString(line)

		possibleAnswer, localScore, _ := FindSingleByteXor(decodedHex)

		// this pattern looks similar to the one in the fn but it is checking a set of 60 lines for a matching line so we are evaluating
		// the result against the other results so best of the best case.
		if localScore > score {
			answer = possibleAnswer
			score = localScore
		}
	}

	return answer
}

// EncodeXorRepeatingKey takes an input sequence string and a key and then uses repeating key xor
// to encode the bytes and returns the byte array
func EncodeXorRepeatingKey(inp string, key string) []byte {
	keyBytes := []byte(key)
	inpBytes := []byte(inp)

	var xord []byte
	var currKeyIdx = 0
	var kbLen = len(keyBytes) - 1

	for _, v := range inpBytes {
		xordByte := xorByte(v, keyBytes[currKeyIdx])
		xord = append(xord, xordByte)

		if currKeyIdx == kbLen {
			currKeyIdx = 0
		} else {
			currKeyIdx += 1
		}
	}

	return xord
}

// GetUnknownRepeatingXorPotentialKeysizes takes a pointer to read bytes from a file that are not encoded, and a low and high value for ranges
// iterates and calculates hamming distance for the n amount of bytes where n is the iterative value from l to h.
// returns a sorted slice of evaluated size and score
func GetUnknownRepeatingXorPotentialKeysizes(d *[]byte, l, h int) []KeysizeEvaluation {
	res := make([]KeysizeEvaluation, 0, h-l)

	for i := l; i < h; i++ {
		block1 := (*d)[0:i]
		block2 := (*d)[i : 2*i]
		block3 := (*d)[2*i : 3*i]
		block4 := (*d)[3*i : 4*i]

		dist1 := hammingDistance(block1, block2)
		dist2 := hammingDistance(block2, block3)
		dist3 := hammingDistance(block3, block4)

		// average them
		avgDist := float64(dist1+dist2+dist3) / 3.0 / float64(i)

		res = append(res, KeysizeEvaluation{
			Keysize: i,
			Score:   avgDist,
		})
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].Score < res[j].Score
	})

	return res
}

// FindPotentialKeysFromKeysizeEvaluation takes an input slice of KeysizeEvaluation and the encoded data and applies each item in the slice (potential keysizes)
// against transposed blocks to evaluate the liklihood of the key and for each possible keysize and returns all calculated possible keys
func FindPotentialKeysFromKeysizeEvaluation(keysizes []KeysizeEvaluation, d *[]byte) [][]byte {
	var keys [][]byte
	for _, v := range keysizes {
		size := v.Keysize
		transposed := transposeBlocks(d, size)

		var key []byte
		for _, block := range transposed {
			_, _, singleByteKey := FindSingleByteXor(block)
			key = append(key, singleByteKey)
		}

		keys = append(keys, key)
	}

	return keys
}

// EvaluateKeyAgainstOriginalData takes a key and a original set of bytes and applies repeating key and scores the output
// returns the score and the decoded bytes
func EvaluateKeyAgainstOriginalData(key []byte, d *[]byte) (int, []byte) {
	textBytes := repeatingKeyXor(*d, key)
	score := evalutatePlainText(textBytes)
	return score, textBytes
}

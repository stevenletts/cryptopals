package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"sort"
	"strings"
)

type fillKey struct {
	length int
	char   byte
}

var makeAndFillCache = map[fillKey][]byte{}

func handleFail(msg string, err error) {
	fmt.Printf("%s\n", msg)
	panic(err)
}

func challenge1() {
	inputExample := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	bytes, err := decodeHex(inputExample)

	if err != nil {
		panic(err)
	}

	encoded := base64.StdEncoding.EncodeToString(bytes)

	if encoded != expected {
		handleFail("failed challenge 1", errors.New("failed challenge 1"))
	}
	fmt.Println("Challenge 1 passed")
}

func challenge2() {
	ipt1 := "1c0111001f010100061a024b53535009181c"
	ipt2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"

	decoded1, _ := decodeHex(ipt1)
	decoded2, _ := decodeHex(ipt2)

	xordSlice, err := xor(decoded1, decoded2)

	if err != nil {
		handleFail("xor fn error in challenge 2", err)
	}

	result := encodeHex(xordSlice)

	if result != expected {
		panic("wtf")
	}

	fmt.Println("Challenge 2 passed")
}

func challenge3() {
	inp := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	answer, _, _ := checkForSingleXorHexEncoded(inp)
	if b := strings.Compare("Cooking MC's like a pound of bacon", string(answer)) == 1; b {
		handleFail("the result was incorrect", errors.New("incorrect string comparison in challnege 3"))
	}
	fmt.Println("Challenge 3 passed")
}

func challenge4() {
	file, err := os.Open("./assets/xor_encoded.txt")

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

		possibleAnswer, localScore, _ := checkForSingleXorHexEncoded(line)

		// this pattern looks similar to the one in the fn but it is checking a set of 60 lines for a matching line so we are evaluating
		// the result against the other results so best of the best case.
		if localScore > score {
			answer = possibleAnswer
			score = localScore
		}
	}

	if b := strings.Compare("Now that the party is jumping", string(answer)) == 1; b {
		handleFail("something went wrong", errors.New("failed in challenge 4"))
	}

	fmt.Println("Challenge 4 passed")
}

func challenge5() {
	inp := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

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

	encoded := encodeHex(xord)

	if strings.Compare(encoded, expected) != 0 {
		panic("failed challenge 5")
	}
	fmt.Println("Challenge 5 passed")
}

func challenge6() []byte {
	// first check the hamming distance of the two example strings is 37 - sanity check
	res := hammingDistanceForStrings("this is a test", "wokka wokka!!!")

	if res != 37 {
		panic("something is wrong in the hamming distance calculator")
	}

	data, err := os.ReadFile("./assets/decrypt_file.txt")
	decoded, err := base64.StdEncoding.DecodeString(string(data))

	if err != nil {
		panic(err)
	}

	keySizesAndScoredSorted := getKeysizesScored(&decoded, 2, 41)
	var final []byte
	var currWinner int

	for i := 0; i < 3; i++ {
		candidateSize := keySizesAndScoredSorted[i].keysize

		transposed := transposeBlocks(&decoded, candidateSize)

		// 3) build the derived key
		var key []byte
		for _, block := range transposed {
			_, _, singleByteKey := checkForSingleXor(block)
			key = append(key, singleByteKey)
		}

		textBytes := repeatingKeyXor(decoded, key)
		// assess textBytes
		score := evalutatePlainText(textBytes)

		if score > currWinner {
			final = textBytes
			currWinner = score
		}
	}



	// fmt.Printf("\nThe first 150 characters of the text are:\n%s\n", string(final[:150]))
	fmt.Println("Challenge 6 passed")
	return final
}

func challenge7() {
	data, _ := os.ReadFile("./assets/aes_encrypted_file.txt")
	decoded, _ := base64.StdEncoding.DecodeString(string(data))

	_, err := decryptAes128Ecb(decoded, []byte("YELLOW SUBMARINE"))

	if err != nil {
		panic("error decrytpting")
	}


//	fmt.Printf("%s", string(text))
}

func decryptAes128Ecb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(data))
	for i, j := 0, 16; i < len(data); i, j = i+16, j+16 {
		cipher.Decrypt(plainText[i:j], data[i:j])
	}
	return plainText, nil
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

// takes a pointer to a sequence of bytes and iterates over them creating slices stored in a map where i..keysize: bytes in ith position
func transposeBlocks(d *[]byte, keysize int) [][]byte {
	ret := make([][]byte, keysize)

	for i, v := range *d {
		ret[i%keysize] = append(ret[i%keysize], v)
	}

	return ret
}

type keysizeEvaluation struct {
	keysize int
	score   float64
}

// takes a pointer to read bytes from a file that are not encoded, and a low and high value for ranges
// iterates and calculates hamming distance for the n amount of bytes where n is the iterative value from l to h.
// returns a sorted slice of evaluated size and score
func getKeysizesScored(d *[]byte, l int, h int) []keysizeEvaluation {

	res := make([]keysizeEvaluation, 0, h-l)

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

		res = append(res, keysizeEvaluation{
			keysize: i,
			score:   avgDist,
		})
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].score < res[j].score
	})

	return res
}

// takes an hexadecimal (base 16) input and decodes it to raw bytes and then xors against every character and
// scores the output providing the highest output as the answer
func checkForSingleXorHexEncoded(inp string) ([]byte, int, byte) {
	decoded, _ := decodeHex(inp)

	return checkForSingleXor(decoded)
}

// takes an input of bytes, a length
func checkForSingleXor(inp []byte) ([]byte, int, byte) {
	var answer []byte
	var score = 0
	var key byte
	length := len(inp)

	for i := 0; i < 256; i++ {
		temp := makeAndFill(length, byte(i))
		res, err := xor(inp, temp)
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

// creates a slice of length l filled with a specific byte b and caches them so they are available for reuse if attempting to iterate a high
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

// simple character weighting system. uses ETAOIN SHRDLU as the scoring mechanism and returns a score.
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

// xor takes two equal length byte slices and returns the exclusive or
// from the bitwise operator on each elemenent sequentially
func xor(s1, s2 []byte) ([]byte, error) {
	if len(s1) != len(s2) {
		return nil, errors.New("length mismatch in xor")
	}

	res := make([]byte, len(s1))

	for i := 0; i < len(res); i++ {
		res[i] = xorByte(s1[i], s2[i])
	}

	return res, nil
}

func xorByte(b1, b2 byte) byte {
	return b1 ^ b2
}

func hammingDistanceForStrings(s1, s2 string) int {
	b1 := []byte(s1)
	b2 := []byte(s2)

	return hammingDistance(b1, b2)
}

func hammingDistance(b1, b2 []byte) int {
	xord, _ := xor(b1, b2)
	var res int

	for _, v := range xord {
		res += bits.OnesCount8(v)
	}

	return res
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func encodeHex(bs []byte) string {
	return hex.EncodeToString(bs)
}

func main() {
	challenge1()
	challenge2()
	challenge3()
	challenge4()
	challenge5()
	challenge6()
	challenge7()
}

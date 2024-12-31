package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
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
	answer, _ := checkForSingleXorEncoded(inp)
	if b := strings.Compare("Cooking MC's like a pound of bacon", string(answer)) == 1; b {
		handleFail("the result was incorrect", errors.New("incorrect string comparison in challnege 3"))
	}
	fmt.Println("Challenge 3 passed")
}

func challenge4() {
	// for this challenge i want to read the file in assets/encoded ... and then when i encounter a set of newline characters then take the buffer and pass
	// it to the challenge 3 logic
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

		possibleAnswer, localScore := checkForSingleXorEncoded(line)

		if localScore > score {
			answer = possibleAnswer
			score = localScore
		}
	}

	if b := strings.Compare("Now that the party is jumping", string(answer)) ==1 ; b {
		handleFail("something went wrong", errors.New("failed in challenge 4"))
	}

	fmt.Println("Challenge 4 passed")
}

func checkForSingleXorEncoded(inp string) ([]byte, int) {
	decoded, _ := decodeHex(inp)
	decodedLen := len(decoded)

	var answer []byte
	var score = 0

	for i := 0; i < 256; i++ {
		temp := makeAndFill(decodedLen, byte(i))
		res, err := xor(decoded, temp)
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
		}
	}

	return answer, score
}

func makeAndFill(l int, c byte) []byte {
	key := fillKey{
		l,
		c,
	}
	v, ok := makeAndFillCache[key]
	if ok {
		return  v
	}

	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = c
	}
	makeAndFillCache[key] = ret

	return ret
}

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

func xor(s1, s2 []byte) ([]byte, error) {
	if len(s1) != len(s2) {
		return nil, errors.New("length mismatch in xor")
	}

	res := make([]byte, len(s1))

	for i := 0; i < len(res); i++ {
		res[i] = s1[i] ^ s2[i]
	}

	return res, nil
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
}

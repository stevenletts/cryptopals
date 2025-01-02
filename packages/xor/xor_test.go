package xor

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestApplyXorSimple(t *testing.T) {
	ipt1 := "1c0111001f010100061a024b53535009181c"
	ipt2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"

	decoded1, _ := hex.DecodeString(ipt1)
	decoded2, _ := hex.DecodeString(ipt2)

	xordSlice, err := ApplyXor(decoded1, decoded2)

	if err != nil {
		t.Fatalf("ApplyXor returned an error: %v", err)
	}

	result := hex.EncodeToString(xordSlice)

	if result != expected {
		t.Fatalf("Failed to correctly ApplyXor. Expected: %s, got: %s", expected, result)
	}
}

func TestFindSingleByteXorSimple(t *testing.T) {
	inp := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expected := "Cooking MC's like a pound of bacon"
	hexDecoded, _ := hex.DecodeString(inp)
	// not testing the score or byte - it is effective enough to assert the actual result only
	answer, _, _ := FindSingleByteXor(hexDecoded)
	strAns := string(answer)

	if strings.Compare(expected, strAns) != 0 {
		t.Fatalf("failed to correctly find the single xor byte used for encoding. Expected %s, got %s", expected, strAns)
	}
}

func TestFindSingleXordLineInFileSimple(t *testing.T) {
	expected := "Now that the party is jumping"
	answer := FindSingleXordLineInFile("./test_files/xor_encoded.txt")
	strAns := strings.TrimSpace(string(answer))
	if strings.Compare(expected, strAns) != 0 {
		t.Fatalf("Failed to find the single Xord line in the file. Expected %s, got %s", expected, strAns)
	}
}

func TestEncodeXorRepeatingKey(t *testing.T) {
	inp := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	xord := EncodeXorRepeatingKey(inp, key)
	encoded := hex.EncodeToString(xord)

	if strings.Compare(encoded, expected) != 0 {
		t.Fatalf("failedTestEncodeXorRepeatingKey expected: %s, got %s", expected, encoded)
	}
}

func TestEvaluateKeyAgainstOriginalData(t *testing.T) {
	data, _ := os.ReadFile("./test_files/decrypt_file.txt")
	decoded, _ := base64.StdEncoding.DecodeString(string(data))

	keySizesAndScoredSorted := GetUnknownRepeatingXorPotentialKeysizes(&decoded, 2, 41)
	keys := FindPotentialKeysFromKeysizeEvaluation(keySizesAndScoredSorted[:4], &decoded)
	var final []byte
	var currWinner int
	for _, k := range keys {
		score, textBytes := EvaluateKeyAgainstOriginalData(k, &decoded)

		if score > currWinner {
			final = textBytes
			currWinner = score
		}
	}

	if strings.Compare(string(final[:33]), "I'm back and I'm ringin' the bell") != 0 {
		t.Fatalf("failed to calculate the key for the data")
	}
}

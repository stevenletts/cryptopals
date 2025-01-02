package main

// convert an hex encoded input to base64 encoded
//func s1c1() {
//	inputExample := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
//	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
//
//	bs, err := hex.DecodeString(inputExample)
//
//	if err != nil {
//		panic(err)
//	}
//
//	encoded := base64.StdEncoding.EncodeToString(bs)
//
//	if encoded != expected {
//		panic(errors.New("challenge 1 failed"))
//	}
//	fmt.Println("Challenge 1 passed")
//}

func s2c2() {
	// the wikipedia article says the ciphertext should be xor'd prior
	// to adding to the next plaintext but cryptopals does not say this bit.
}

func main() {
}

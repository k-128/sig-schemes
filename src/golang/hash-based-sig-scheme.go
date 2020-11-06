package main

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"math/rand"
	"time"
)

type KeyPair [2][512][]byte

type Signature [512][]byte

func GetHash(b []byte) []byte {
	h := sha512.New()
	h.Write(b)
	return h.Sum(nil)
}

func GenerateKeys() (KeyPair, KeyPair) {
	var secKeyPair KeyPair // 2x n hashes
	var pubKeyPair KeyPair // Hashed secKeyPair hashes
	for i, key := range secKeyPair {
		for j, _ := range key {
			bs := make([]byte, 4)
			if _, err := rand.Read(bs); err == nil {
				secKeyPair[i][j] = GetHash(bs)
				pubKeyPair[i][j] = GetHash(secKeyPair[i][j][:])
			}
		}
	}
	return secKeyPair, pubKeyPair
}

func Sign(secKeyPair KeyPair, message string) Signature {
	var sig Signature
	msgHash := GetHash([]byte(message))
	for i, msgHashByte := range msgHash {
		for j, binRepr := range fmt.Sprintf("%08b", msgHashByte) {
			if fmt.Sprintf("%c", binRepr) == "0" {
				sig[8*i+j] = secKeyPair[0][8*i+j]
			} else {
				sig[8*i+j] = secKeyPair[1][8*i+j]
			}
		}
	}
	return sig
}

func Verify(pubKeyPair KeyPair, sig Signature) bool {
	for i := 0; i < len(pubKeyPair[0]); i++ {
		sigHash := GetHash(sig[i][:])

		if !bytes.Equal(pubKeyPair[0][i][:], sigHash[:]) &&
			!bytes.Equal(pubKeyPair[1][i][:], sigHash[:]) {
			return false
		}
	}
	return true
}

func HashBasedSigSchemeTest() {
	rand.Seed(time.Now().Unix())
	secKeyPair, pubKeyPair := GenerateKeys()
	sig := Sign(secKeyPair, "msg")
	fmt.Printf("valid sig: %t\n", Verify(pubKeyPair, sig))
}

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/diplom-mn/chaincode-go-certificate/chaincode"
)

func main() {
	privKeyRaw := os.Getenv("PRIVKEY")
	argPath := os.Getenv("CDA_PATH")
	argData, err := os.ReadFile(argPath)
	if err != nil {
		panic(err)
	}
	argRaw := string(argData)
	var arg chaincode.CreateCertificateArg
	json.Unmarshal([]byte(argRaw), &arg)
	privKeyPem, _ := pem.Decode([]byte(privKeyRaw))
	privKey, err := x509.ParseECPrivateKey(privKeyPem.Bytes)
	if err != nil {
		panic(err)
	}
	_, hashBytes, err := chaincode.NewCertificateClaimsHash(arg.Claims)
	if err != nil {
		panic(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hashBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
}

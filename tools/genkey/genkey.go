package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	err := gen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}
}

func gen() error {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("could not generate key : %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("could not encode key : %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(der)

	fmt.Println("Insecure RSA key for unit testing")
	fmt.Println(b64)

	return nil
}

package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: go run ./scripts/hash_password.go <password>")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(hash))
}

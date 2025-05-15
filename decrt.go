package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

func decryptPassword(encryptedPass string, keyFile string) (string, error) {
	if encryptedPass == "" {
		return "", nil
	}

	// 读取加密密钥
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("Cannot read encryption key: %v", err)
	}

	key := sha256.Sum256(keyData)
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPass)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("Ciphertext too short")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run decrt.go <base64_encrypted_password> <key_file_path>")
		os.Exit(1)
	}

	decrypted, err := decryptPassword(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting password: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Decrypted password: ", decrypted)
}

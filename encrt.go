package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

// 加密密码 - 用于生成配置文件中的加密密码
func encryptPassword(password string, keyFile string) (string, error) {
	// 如果密码为空，返回空
	if password == "" {
		return "", nil
	}

	// 读取或生成加密密钥
	var keyData []byte
	if fileExists(keyFile) {
		var err error
		keyData, err = os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("Cannot read encryption key: %v", err)
		}
	} else {
		// 生成随机密钥
		keyData = make([]byte, 32)
		if _, err := rand.Read(keyData); err != nil {
			return "", fmt.Errorf("Cannot generate encryption key: %v", err)
		}

		// 保存密钥到文件，并设置严格权限
		if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
			return "", fmt.Errorf("Cannot save encryption key: %v", err)
		}
	}

	key := sha256.Sum256(keyData)
	plaintext := []byte(password)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	// IV需要是唯一的，但不需要安全
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 加密
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// 转换为base64便于存储
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run encrt.go <password> <key_file_path>")
		os.Exit(1)
	}

	decrypted, err := encryptPassword(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting password: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Encrypted password: ", decrypted)
}

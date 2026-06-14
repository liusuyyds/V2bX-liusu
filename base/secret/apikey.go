package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultAPIKeySecretFile = "/etc/qingsu/apikey.secret"
	EnvAPIKeySecret         = "QINGSU_API_KEY_SECRET"
	EnvAPIKeySecretFile     = "QINGSU_API_KEY_SECRET_FILE"
	apiKeyCipherPrefix      = "enc:v1:"
)

func IsEncryptedAPIKey(value string) bool {
	return strings.HasPrefix(value, apiKeyCipherPrefix)
}

func ResolveAPIKeySecret(secretFile string, create bool) (secret string, source string, err error) {
	if value := strings.TrimSpace(os.Getenv(EnvAPIKeySecret)); value != "" {
		return value, "env:" + EnvAPIKeySecret, nil
	}

	if secretFile == "" {
		secretFile = strings.TrimSpace(os.Getenv(EnvAPIKeySecretFile))
	}
	if secretFile == "" {
		secretFile = DefaultAPIKeySecretFile
	}

	data, err := os.ReadFile(secretFile)
	if err == nil {
		secret = strings.TrimSpace(string(data))
		if secret == "" {
			return "", "", fmt.Errorf("api key secret file is empty: %s", secretFile)
		}
		return secret, secretFile, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", "", fmt.Errorf("read api key secret file error: %w", err)
	}
	if !create {
		return "", "", fmt.Errorf("api key secret file not found: %s", secretFile)
	}

	if err = os.MkdirAll(filepath.Dir(secretFile), 0700); err != nil {
		return "", "", fmt.Errorf("create api key secret dir error: %w", err)
	}
	keyBytes := make([]byte, 32)
	if _, err = rand.Read(keyBytes); err != nil {
		return "", "", fmt.Errorf("generate api key secret error: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(keyBytes)
	if err = os.WriteFile(secretFile, []byte(secret+"\n"), 0600); err != nil {
		return "", "", fmt.Errorf("write api key secret file error: %w", err)
	}
	return secret, secretFile, nil
}

func EncryptAPIKey(plainText string, secret string) (string, error) {
	plainText = strings.TrimSpace(plainText)
	if plainText == "" {
		return "", errors.New("api key is empty")
	}
	block, err := aes.NewCipher(deriveKey(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plainText), nil)
	payload := append(nonce, sealed...)
	return apiKeyCipherPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecryptAPIKey(value string, secret string) (string, error) {
	if !IsEncryptedAPIKey(value) {
		return value, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, apiKeyCipherPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted api key error: %w", err)
	}
	block, err := aes.NewCipher(deriveKey(secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("encrypted api key payload is invalid")
	}
	nonce := payload[:gcm.NonceSize()]
	cipherText := payload[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt encrypted api key error: %w", err)
	}
	return string(plainText), nil
}

func deriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return sum[:]
}

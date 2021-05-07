// Package secret provides simple utilities for encrypting and decrypting data.
package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// ErrDecryptFailed is returned when Decrypt is unable to decrypt due to
// invalid inputs.
var ErrDecryptFailed = errors.New("decrypt failed")

// Encrypt data. Uses AES-256-CFB encrypter.
func Encrypt(key string, data []byte) ([]byte, error) {
	keyb := sha256.Sum256([]byte(key))
	ciph, err := aes.NewCipher(keyb[:])
	if err != nil {
		return nil, err
	}
	// The iv is added to the front of the final payload.
	encdata := make([]byte, aes.BlockSize*2+len(data))
	if _, err := rand.Read(encdata[:aes.BlockSize]); err != nil {
		return nil, err
	}
	// The iv is also added to the front of the encrypted data so we can
	// verify after decrypting.
	dataiv := make([]byte, aes.BlockSize+len(data))
	copy(dataiv, encdata[:aes.BlockSize])
	copy(dataiv[aes.BlockSize:], data)
	cipher.NewCFBEncrypter(ciph, encdata[:aes.BlockSize]).
		XORKeyStream(encdata[aes.BlockSize:], dataiv)
	return encdata, nil
}

// Decrypt data. Uses AES-256-CFB decrypter.
func Decrypt(key string, data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, ErrDecryptFailed
	}
	keyb := sha256.Sum256([]byte(key))
	ciph, err := aes.NewCipher(keyb[:])
	if err != nil {
		return nil, err
	}
	decdata := make([]byte, len(data)-aes.BlockSize)
	cipher.NewCFBDecrypter(ciph, data[:aes.BlockSize]).
		XORKeyStream(decdata, data[aes.BlockSize:])
	if len(decdata) < aes.BlockSize {
		return nil, ErrDecryptFailed
	}
	if !bytes.Equal(data[:aes.BlockSize], decdata[:aes.BlockSize]) {
		return nil, ErrDecryptFailed
	}
	return decdata[aes.BlockSize:], nil
}

package secret

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
	"time"
)

func TestEncrypt(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	for time.Since(start) < time.Second*2 {
		key := make([]byte, 32)
		rand.Read(key[:])
		data := make([]byte, rand.Intn(256))
		rand.Read(data[:])

		encdata, err := Encrypt(string(key), data)
		if err != nil {
			t.Fatalf("encrypt: %s: key: %s, data: %s",
				err.Error(), hex.EncodeToString(key), hex.EncodeToString(data))
		}
		decdata, err := Decrypt(string(key), encdata)
		if err != nil {
			t.Fatalf("decrypt: %s: key: %s, data: %s",
				err.Error(), hex.EncodeToString(key), hex.EncodeToString(data))
		}
		if !bytes.Equal(decdata, data) {
			t.Fatalf("mismatch: key: %s, data: %s",
				hex.EncodeToString(key), hex.EncodeToString(data))
		}
	}

}

func TestSimple(t *testing.T) {
	key := "hello world"
	data := []byte("hello jello")

	encdata, err := Encrypt(key, data)
	if err != nil {
		panic(err)
	}

	decdata, err := Decrypt("hello world", encdata)
	if err != nil {
		panic(err)
	}

	if string(decdata) != string(data) {
		panic("mismatch")
	}
}

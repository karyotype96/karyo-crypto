package cipher

import (
	"fmt"
)

// note: this works exactly the same way forwards as it does backwards
func XOREncrypt(msg []byte, key string) ([]byte, error) {
	keyBytes := []byte(key)

	if len(keyBytes) < 1 {
		return nil, fmt.Errorf("key length must be greater than 0")
	}

	for i, c := range msg {
		msg[i] = c ^ keyBytes[i%len(keyBytes)]
	}

	return msg, nil
}

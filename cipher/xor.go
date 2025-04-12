package cipher

import (
	"fmt"
)

// note: this works exactly the same way forwards as it does backwards
func XOREncrypt(msg []byte, key []byte) ([]byte, error) {

	if len(key) < 1 {
		return nil, fmt.Errorf("key length must be greater than 0")
	}

	for i, c := range msg {
		msg[i] = c ^ key[i%len(key)]
	}

	return msg, nil
}

package cipher

import (
	"fmt"
)

const ALPHABET_COUNT = 26

func CaesarEncrypt(msg []byte, key int) ([]byte, error) {
	if key < 1 || key > 25 {
		return nil, fmt.Errorf("key must be greater than 0 and less than 26")
	}

	for i, _ := range msg {
		if msg[i] >= 'A' && msg[i] <= 'Z' {
			msg[i] = (((msg[i] - 'A') + byte(key)) % ALPHABET_COUNT) + 'A'
		}

		if msg[i] >= 'a' && msg[i] <= 'z' {
			msg[i] = (((msg[i] - 'a') + byte(key)) % ALPHABET_COUNT) + 'a'
		}
	}

	return msg, nil
}

// this is technically not a necessary function, but I'm including it for completeness
func CaesarDecrypt(msg []byte, key int) ([]byte, error) {
	reverseKey := ALPHABET_COUNT - key

	return CaesarEncrypt(msg, reverseKey)
}

package cipher

import (
	"fmt"
)

const ALPHABET_COUNT = 26

func CaesarEncrypt(msg string, key int) (string, error) {
	if key < 1 || key > 25 {
		return "", fmt.Errorf("key must be greater than 0 and less than 26")
	}

	msgBytes := []byte(msg)

	for i, _ := range msgBytes {
		if msgBytes[i] >= 'A' && msgBytes[i] <= 'Z' {
			msgBytes[i] = (((msgBytes[i] - 'A') + byte(key)) % ALPHABET_COUNT) + 'A'
		}

		if msgBytes[i] >= 'a' && msgBytes[i] <= 'z' {
			msgBytes[i] = (((msgBytes[i] - 'a') + byte(key)) % ALPHABET_COUNT) + 'a'
		}
	}

	return string(msgBytes), nil
}

// this is technically not a necessary function, but I'm including it for completeness
func CaesarDecrypt(msg string, key int) (string, error) {
	reverseKey := ALPHABET_COUNT - key

	return CaesarEncrypt(msg, reverseKey)
}

package cipher

import (
	"fmt"
	"strings"
)

func BaconianEncrypt(msg string) string {
	baconMap := make(map[byte]string)

	for i, b := range []byte("abcdefghijklmnopqrstuvwxyz") {
		char1, char2, char3, char4, char5 := 'A', 'A', 'A', 'A', 'A'

		if i&0b00001 > 0 {
			char1 = 'B'
		}
		if i&0b00010 > 0 {
			char2 = 'B'
		}
		if i&0b00100 > 0 {
			char3 = 'B'
		}
		if i&0b01000 > 0 {
			char4 = 'B'
		}
		if i&0b10000 > 0 {
			char5 = 'B'
		}

		resultValue := fmt.Sprintf("%c%c%c%c%c", char5, char4, char3, char2, char1)

		baconMap[b] = resultValue
	}

	resultArray := make([]string, len(msg))

	for i, b := range []byte(msg) {
		key := b
		if key >= 'A' && key <= 'Z' {
			key += 32
		}

		v, ok := baconMap[byte(key)]
		if ok {
			resultArray[i] = v
		}
	}

	return strings.Join(resultArray, " ")
}

func BaconianDecrypt(msg string) (string, error) {
	baconMap := make(map[string]byte)

	for i, b := range []byte("abcdefghijklmnopqrstuvwxyz") {
		char1, char2, char3, char4, char5 := 'A', 'A', 'A', 'A', 'A'

		if i&0b00001 > 0 {
			char1 = 'B'
		}
		if i&0b00010 > 0 {
			char2 = 'B'
		}
		if i&0b00100 > 0 {
			char3 = 'B'
		}
		if i&0b01000 > 0 {
			char4 = 'B'
		}
		if i&0b10000 > 0 {
			char5 = 'B'
		}

		resultValue := fmt.Sprintf("%c%c%c%c%c", char5, char4, char3, char2, char1)

		baconMap[resultValue] = b
	}

	items := strings.Split(msg, " ")

	resultMsg := make([]byte, len(items))

	for i, s := range items {
		v, ok := baconMap[s]
		if ok {
			resultMsg[i] = v
		} else {
			return "", fmt.Errorf("invalid message string")
		}
	}

	return string(resultMsg), nil
}

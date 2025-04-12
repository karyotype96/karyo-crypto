package encoding

import (
	"fmt"
	"strings"
)

const CHAR_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func Base64Encode(message []byte) ([]byte, error) {
	if len(message) < 1 {
		return nil, fmt.Errorf("cannot encode an empty byte slice")
	}

	baseBuffer := make([]byte, 0)
	for byteIndex := 0; byteIndex < len(message); byteIndex += 3 {
		var byteBuffer [4]byte

		byteBuffer[0] = ((0b11111100 & message[byteIndex]) >> 2) & 0b00111111
		byteBuffer[1] = ((0b00000011 & message[byteIndex]) << 4) & 0b00110000
		byteBuffer[2] = byte('=')
		byteBuffer[3] = byte('=')

		if byteIndex+1 >= len(message) {
			baseBuffer = append(baseBuffer, byteBuffer[0:4]...)
			break
		}

		byteBuffer[1] |= ((0b11110000 & message[byteIndex+1]) >> 4) & 0b00001111
		byteBuffer[2] = ((0b00001111 & message[byteIndex+1]) << 2) & 0b00111100
		if byteIndex+2 >= len(message) {
			baseBuffer = append(baseBuffer, byteBuffer[0:4]...)
			break
		}

		byteBuffer[2] |= (0b11000000 & message[byteIndex+2] >> 6) & 0b00000011
		byteBuffer[3] = (0b00111111 & message[byteIndex+2])
		baseBuffer = append(baseBuffer, byteBuffer[:]...)
	}

	for encodeIndex, _ := range baseBuffer {
		if baseBuffer[encodeIndex] == '=' {
			continue
		}

		baseBuffer[encodeIndex] = byte(CHAR_MAP[int(baseBuffer[encodeIndex])])
	}

	return baseBuffer, nil
}

func Base64Decode(encoded []byte) ([]byte, error) {
	if len(encoded)%4 != 0 {
		return nil, fmt.Errorf("length of encoded byte slice must be a multiple of 4")
	}

	baseBuffer := make([]byte, 0)
	for byteIndex := 0; byteIndex < len(encoded); byteIndex += 4 {
		var decodeBuffer [4]byte

		for i := 0; i < len(decodeBuffer); i++ {
			if encoded[byteIndex+i] == byte('=') {
				decodeBuffer[i] = 0
			} else {
				decodeBuffer[i] = byte(strings.Index(CHAR_MAP, string(encoded[byteIndex+i])))
			}
		}

		var byteBuffer [3]byte

		byteBuffer[0] = ((decodeBuffer[0] << 2) & 0b11111100) + ((decodeBuffer[1] >> 4) & 0b00000011)
		byteBuffer[1] = ((decodeBuffer[1] << 4) & 0b11110000) + ((decodeBuffer[2] >> 2) & 0b00001111)
		byteBuffer[2] = ((decodeBuffer[2] << 6) & 0b11000000) + ((decodeBuffer[3]) & 0b00111111)

		baseBuffer = append(baseBuffer, byteBuffer[:]...)
	}

	return baseBuffer, nil
}

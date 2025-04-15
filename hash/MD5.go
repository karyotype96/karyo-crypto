package hash

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

type MD_Buffer struct {
	A uint32
	B uint32
	C uint32
	D uint32
}

type MD5 struct {
	message []byte
	buf     MD_Buffer
}

// auxiliary functions and constants
var K = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

var s = [...]int{7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21}

func F(B uint32, C uint32, D uint32) uint32 {
	return (B & C) | (^B & D)
}
func G(B uint32, C uint32, D uint32) uint32 {
	return (B & D) | (C & ^D)
}
func H(B uint32, C uint32, D uint32) uint32 {
	return B ^ C ^ D
}
func I(B uint32, C uint32, D uint32) uint32 {
	return C ^ (B | ^D)
}

// MD Buffer-specific functions and methods
func CreateMDBuffer() MD_Buffer {
	return MD_Buffer{A: 0x67452301, B: 0xEFCDAB89, C: 0x98BADCFE, D: 0x10325476}
}

func (m *MD_Buffer) ResetBuffer() {
	m.A = 0x67452301
	m.B = 0xEFCDAB89
	m.C = 0x98BADCFE
	m.D = 0x10325476
}

// MD5-specific functions and methods

/* public functions/methods */
func CreateMD5() MD5 {
	return MD5{
		message: make([]byte, 0),
		buf:     CreateMDBuffer(),
	}
}

func (m *MD5) Write(toAdd []byte) {
	m.message = append(m.message, toAdd...)
}

func (m *MD5) Clear() {
	m.message = make([]byte, 0)
}

func (m *MD5) Digest() []byte {
	m.buf.ResetBuffer()

	paddedMsg := bytes.NewBuffer([]byte(m.message))
	paddedMsg.WriteByte(0x80)
	for paddedMsg.Len()%64 != 56 {
		paddedMsg.WriteByte(0x00)
	}
	length := uint64(len(s)) * 8
	binary.Write(paddedMsg, binary.LittleEndian, length)
	// fmt.Printf("full padded msg: %x, total length: %d\n", paddedMsg, len(paddedMsg))

	var buffer [16]uint32
	for binary.Read(paddedMsg, binary.LittleEndian, buffer[:]) == nil {
		AA := m.buf.A
		BB := m.buf.B
		CC := m.buf.C
		DD := m.buf.D

		for i := 0; i < 64; i++ {
			var f uint32
			bufferIndex := i
			round := i >> 4
			if i >= 0 && i < 16 {
				f = F(BB, CC, DD)
			} else if i >= 16 && i < 32 {
				f = G(BB, CC, DD)
				bufferIndex = (bufferIndex*5 + 1) & 0x0F
			} else if i >= 32 && i < 48 {
				f = H(BB, CC, DD)
				bufferIndex = (bufferIndex*3 + 5) & 0x0F
			} else if i >= 48 && i < 64 {
				f = I(BB, CC, DD)
				bufferIndex = (bufferIndex * 7) & 0x0F
			}

			shiftCount := s[(round<<2)|(i&3)]

			AA += f + buffer[bufferIndex] + K[i]

			AA, DD, CC, BB = DD, CC, BB, bits.RotateLeft32(AA, shiftCount)+BB
		}

		m.buf.A += AA
		m.buf.B += BB
		m.buf.C += CC
		m.buf.D += DD
	}

	result := make([]byte, 16)
	binary.Write(bytes.NewBuffer(result[:0]), binary.LittleEndian, []uint32{m.buf.A, m.buf.B, m.buf.C, m.buf.D})

	return result
}

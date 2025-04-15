package hash

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

var k [64]uint32 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

type SHA256 struct {
	message []byte
}

func CreateSHA256() SHA256 {
	return SHA256{
		message: make([]byte, 0),
	}
}

func (m *SHA256) Write(b []byte) {
	m.message = append(m.message, b...)
}

func (m *SHA256) Clear() {
	m.message = make([]byte, 0)
}

func (m *SHA256) Digest() []byte {
	paddedMsg := bytes.NewBuffer(m.message)
	origLength := uint64(paddedMsg.Len() * 8)

	paddedMsg.WriteByte(0x80)
	for paddedMsg.Len()%64 != 56 {
		paddedMsg.WriteByte(0x00)
	}

	binary.Write(paddedMsg, binary.BigEndian, origLength)

	var h0 uint32 = 0x6a09e667
	var h1 uint32 = 0xbb67ae85
	var h2 uint32 = 0x3c6ef372
	var h3 uint32 = 0xa54ff53a
	var h4 uint32 = 0x510e527f
	var h5 uint32 = 0x9b05688c
	var h6 uint32 = 0x1f83d9ab
	var h7 uint32 = 0x5be0cd19

	for blockNum := 0; blockNum < paddedMsg.Len(); blockNum += 64 {
		block := make([]byte, 64)
		copy(block, paddedMsg.Bytes()[blockNum:blockNum+64])

		M := make([]uint32, 64)
		for i := 0; i < len(block); i += 4 {
			M[i/4] = binary.BigEndian.Uint32(block[i : i+4])
		}

		for i := 16; i < len(M); i++ {
			word1 := M[i-16]
			word2 := M[i-7]

			sigma0 := bits.RotateLeft32(M[i-15], -7) ^ bits.RotateLeft32(M[i-15], -18) ^ (M[i-15] >> 3)
			sigma1 := bits.RotateLeft32(M[i-2], -17) ^ bits.RotateLeft32(M[i-2], -19) ^ (M[i-2] >> 10)

			M[i] = word1 + sigma0 + word2 + sigma1
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7
		for i := 0; i < 64; i++ {
			S1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			ch := (e & f) ^ ((^e) & g)
			temp1 := h + S1 + ch + k[i] + M[i]
			S0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			h, g, f, e, d, c, b, a = g, f, e, d+temp1, c, b, a, temp1+temp2
		}

		h0, h1, h2, h3, h4, h5, h6, h7 = h0+a, h1+b, h2+c, h3+d, h4+e, h5+f, h6+g, h7+h
	}

	result := make([]byte, 32)
	binary.Write(bytes.NewBuffer(result[:0]), binary.BigEndian, []uint32{h0, h1, h2, h3, h4, h5, h6, h7})

	return result
}

package crypto

import (
	"crypto/sha512"
	"hash"
)

func secureRandomize(h hash.Hash, data []byte, rounds int) []byte {
	for i := 0; i < rounds; i++ {
		h.Write(data)
		h.Write([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		data = h.Sum(nil)
		h.Reset()
	}
	return data
}

func GenerateKey(password []byte, salt []byte, iterations int, keySize int) []byte {
	h := sha512.New()
	key := make([]byte, keySize)

	h.Write(password)
	h.Write(salt)
	current := h.Sum(nil)
	h.Reset()

	for i := 0; i < iterations; i++ {
		current = secureRandomize(h, current, 5)
		for j := 0; j < len(current); j++ {
			current[j] ^= byte(i + j)
		}
	}

	for i := 0; i < keySize; i += len(current) {
		copy(key[i:], current)
		current = secureRandomize(h, current, 1)
	}

	return key[:keySize]
}

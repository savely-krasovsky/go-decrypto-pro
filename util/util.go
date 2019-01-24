package util

import (
	"errors"
	"hash"
)

func Reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

// CryptoPro Key Derivation Function
func DeriveKey(hasher hash.Hash, salt, passphrase []byte) ([]byte, error) {
	// GOST R 34.11-94 - B=32b, L=32b
	// GOST R 34.11-256 - B=64b, L=32b
	// GOST R 34.11-512 - B=64b, L=64b
	bs := hasher.BlockSize()

	if len(passphrase)*4 > 1024 {
		return nil, errors.New("passphrase cannot be longer than 256 symbols")
	}

	// Making it four times bigger. Why? I don't know, really
	pin := make([]byte, len(passphrase)*4)
	for i := 0; i < len(passphrase); i++ {
		pin[i*4] = passphrase[i]
	}

	// First stage, getting hash with salt and optional passphrase
	hasher.Write(salt)
	if len(passphrase) != 0 {
		hasher.Write(pin)
	}
	hash := hasher.Sum(nil)
	hasher.Reset()

	// Create base and secondary material byte arrays
	c := []byte("DENEFH028.760246785.IUEFHWUIO.EF")
	if bs > 32 {
		c = append(c, make([]byte, 32)...)
	}
	m0 := make([]byte, bs)
	m1 := make([]byte, bs)

	// Define count of iterations
	iterations := 2
	if len(passphrase) != 0 {
		iterations = 2000
	}

	// Second stage, multi iterative hashing
	for j := 0; j < iterations; j++ {
		for i := 0; i < bs; i++ {
			m0[i] = c[i] ^ 0x36
			m1[i] = c[i] ^ 0x5C
		}

		hasher.Write(m0)
		hasher.Write(hash)
		hasher.Write(m1)
		hasher.Write(hash)

		c = hasher.Sum(nil)
		if bs > 32 && len(c) == 32 {
			c = append(c, make([]byte, 32)...)
		}
		hasher.Reset()
	}

	// Third stage, yet hashing with salt
	for i := 0; i < bs; i++ {
		m0[i] = c[i] ^ 0x36
		m1[i] = c[i] ^ 0x5C
	}

	hasher.Write(m0)
	hasher.Write(salt)
	hasher.Write(m1)
	if len(passphrase) != 0 {
		hasher.Write(pin)
	}

	c = hasher.Sum(nil)
	if bs > 32 && len(c) == 32 {
		c = append(c, make([]byte, 32)...)
	}
	hasher.Reset()

	hasher.Write(c)
	return hasher.Sum(nil), nil
}

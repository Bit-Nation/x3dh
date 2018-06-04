package x3dh

import (
	"golang.org/x/crypto/curve25519"
	"io"
)

type Curve25519 struct {
	randSource io.Reader
}

func NewCurve25519(randSource io.Reader) Curve25519 {
	return Curve25519{
		randSource: randSource,
	}
}

// calculate a diffie hellman key exchange
// with given key pair
func (c *Curve25519) KeyExchange(dh DHPair) [32]byte {

	var (
		sharedSecret [32]byte
		priv         [32]byte = dh.PrivateKey
		pub          [32]byte = dh.PublicKey
	)

	curve25519.ScalarMult(&sharedSecret, &priv, &pub)

	return sharedSecret

}

// prefix for curve25519 is a byte array
// of length 32 filled with 0xFF
func (c *Curve25519) PreFix() []byte {

	return []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}

}

// create a new curve25519 key pair from a random source
func (c *Curve25519) GenerateKeyPair() (KeyPair, error) {

	var priv [32]byte

	// fill private key
	_, err := c.randSource.Read(priv[:])
	if err != nil {
		return KeyPair{}, err
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &priv)

	return KeyPair{
		PrivateKey: priv,
		PublicKey:  pubKey,
	}, nil

}

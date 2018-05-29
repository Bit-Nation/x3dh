package x3dh

// key pair for diffie hellman key exchange
type DHPair struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
}

// interface for the curve that should be used by x3dh
// we currently only support curve25519
type Curve interface {
	KeyExchange(keys DHPair) [32]byte
	PreFix() []byte
	GenerateKeyPair() (KeyPair, error)
}

type KeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

type PrivateKey [32]byte
type PublicKey [32]byte

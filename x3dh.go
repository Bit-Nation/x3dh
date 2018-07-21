package x3dh

import (
	"errors"
	"hash"

	hkdf "golang.org/x/crypto/hkdf"
)

// returned in case the pre key bundle signature is invalid
var PreKeyBundleInvalidSignature = errors.New("the signature of the received pre key bundle is invalid")

type ProtocolInitialisation struct {
	RemoteIdKey        PublicKey
	RemoteEphemeralKey PublicKey
	MyOneTimePreKey    *PrivateKey
	MySignedPreKey     PrivateKey
}

type InitializedProtocol struct {
	SharedSecret      SharedSecret
	UsedOneTimePreKey *PublicKey
	UsedSignedPreKey  PublicKey
	EphemeralKey      PublicKey
}

// create a new X3dh key agreement protocol
// info is just your protocol name. Something like ("pangea")
// myIDKey is your curve25519 key pair
func New(c Curve, h hash.Hash, info string, myIDKey KeyPair) X3dh {
	return X3dh{
		curve:     c,
		hash:      h,
		info:      info,
		idKeyPair: myIDKey,
	}
}

// the shared secret between you and the partner
type SharedSecret = [32]byte

type X3dh struct {
	curve     Curve
	hash      hash.Hash
	info      string
	idKeyPair KeyPair
}

// kdf derives the final secret between you and your partner
// from "key material", which is made of a few concatenated
// byte slices (output from diffie hellman key exchanges)
func (x *X3dh) kdf(keyMaterial []byte) (SharedSecret, error) {

	// create reader
	r := hkdf.New(
		func() hash.Hash {
			return x.hash
		},
		append(x.curve.PreFix(), keyMaterial...),
		make([]byte, 32), []byte(x.info),
	)

	// fill the shared secret
	var secret [32]byte
	_, err := r.Read(secret[:])
	return secret, err

}

func (x *X3dh) NewKeyPair() (KeyPair, error) {
	return x.curve.GenerateKeyPair()
}

// calculate a shared secret based on a received preKeyBundle
func (x *X3dh) CalculateSecret(b PreKeyBundle) (InitializedProtocol, error) {

	// verify that the signature of the pre key bundle is valid
	valid, err := b.ValidSignature()
	if err != nil {
		return InitializedProtocol{}, err
	}
	if !valid {
		return InitializedProtocol{}, PreKeyBundleInvalidSignature
	}

	// create ephemeral key
	ephemeralKey, err := x.curve.GenerateKeyPair()
	if err != nil {
		return InitializedProtocol{}, err
	}

	// first step with our identity private key
	// and remote signed pre key
	dh1 := x.curve.KeyExchange(DHPair{
		PrivateKey: x.idKeyPair.PrivateKey,
		PublicKey:  b.SignedPreKey(),
	})

	// second step with our ephemeral key
	// and the remote identity key
	dh2 := x.curve.KeyExchange(DHPair{
		PrivateKey: ephemeralKey.PrivateKey,
		PublicKey:  b.IdentityKey(),
	})

	// third step with our ephemeral key
	// and the remote signed pre key
	dh3 := x.curve.KeyExchange(DHPair{
		PrivateKey: ephemeralKey.PrivateKey,
		PublicKey:  b.SignedPreKey(),
	})

	// concat the byte sequences
	// (dh1 || dh2 || dh3)
	km := append(dh1[:], dh2[:]...)
	km = append(km, dh3[:]...)

	// only execute this step if the one time pre key is present.
	// the protocol can work without it tho it's recommended to use them.
	if b.OneTimePreKey() != nil {

		// fourth step with our ephemeral key
		// and the remote one time pre key
		dh4 := x.curve.KeyExchange(DHPair{
			PrivateKey: ephemeralKey.PrivateKey,
			PublicKey:  *b.OneTimePreKey(),
		})

		km = append(km, dh4[:]...)

	}

	s, err := x.kdf(km)

	return InitializedProtocol{
		SharedSecret:      s,
		UsedOneTimePreKey: b.OneTimePreKey(),
		UsedSignedPreKey:  b.SignedPreKey(),
		EphemeralKey:      ephemeralKey.PublicKey,
	}, err

}

// calculate secret based on received on data from initial message
func (x *X3dh) SecretFromRemote(c ProtocolInitialisation) (SharedSecret, error) {

	// first step with our signed pre key
	// and the remote id key
	dh1 := x.curve.KeyExchange(DHPair{
		PrivateKey: c.MySignedPreKey,
		PublicKey:  c.RemoteIdKey,
	})

	// second step with our identity key
	// and the remote ephemeral key
	dh2 := x.curve.KeyExchange(DHPair{
		PrivateKey: x.idKeyPair.PrivateKey,
		PublicKey:  c.RemoteEphemeralKey,
	})

	// third step with our signed pre key
	// and the remote ephemeral key
	dh3 := x.curve.KeyExchange(DHPair{
		PrivateKey: c.MySignedPreKey,
		PublicKey:  c.RemoteEphemeralKey,
	})

	// concat all the byte arrays
	km := append(dh1[:], dh2[:]...)
	km = append(km, dh3[:]...)

	// only calculate with the one time pre key if
	if c.MyOneTimePreKey != nil {

		// fourth step with our one time pre key
		// and the remote ephemeral key
		dh4 := x.curve.KeyExchange(DHPair{
			PrivateKey: *c.MyOneTimePreKey,
			PublicKey:  c.RemoteEphemeralKey,
		})

		km = append(km, dh4[:]...)

	}

	return x.kdf(km)

}

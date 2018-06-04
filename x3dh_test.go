package x3dh

import (
	"crypto/sha256"
	"crypto/rand"
	"testing"

	
	require "github.com/stretchr/testify/require"
)

const testProtocolName = "testing"

func TestX3dh_CalculateSecretNoOneTimePreKey(t *testing.T) {

	c := NewCurve25519(rand.Reader)

	// alice id key pair
	aliceIdKeyPair, err := c.GenerateKeyPair()
	require.Nil(t, err)

	// bob id key pair
	bobIdKeyPair, err := c.GenerateKeyPair()
	require.Nil(t, err)

	// bob signed pre key pair
	bobSignedPreKey, err := c.GenerateKeyPair()

	aliceX := New(&c, sha256.New(), testProtocolName, aliceIdKeyPair)

	// calculate secret with bob's pre key bundle
	initializedProtocol, err := aliceX.CalculateSecret(TestPreKeyBundle{
		validSignature:  true,
		identityKey:     bobIdKeyPair.PublicKey,
		signedPreKey:    bobSignedPreKey.PublicKey,
		preKeySignature: []byte(""),
	})
	require.Nil(t, err)

	bobX := New(&c, sha256.New(), testProtocolName, bobIdKeyPair)
	secretBob, err := bobX.SecretFromRemote(ProtocolInitialisation{
		RemoteIdKey:        aliceIdKeyPair.PublicKey,
		RemoteEphemeralKey: initializedProtocol.EphemeralKey,
		MySignedPreKey:     bobSignedPreKey.PrivateKey,
	})
	require.Nil(t, err)

	require.Equal(t, initializedProtocol.SharedSecret, secretBob)

}

func TestX3dh_CalculateSecretInvalidSignature(t *testing.T) {

	c := NewCurve25519(rand.Reader)

	// alice id key pair
	aliceIdKeyPair, err := c.GenerateKeyPair()
	require.Nil(t, err)

	aliceX := New(&c, sha256.New(), testProtocolName, aliceIdKeyPair)

	// since we set the signature to invalid an error should be returned
	_, err = aliceX.CalculateSecret(TestPreKeyBundle{
		validSignature: false,
	})
	require.EqualError(t, err, PreKeyBundleInvalidSignature.Error())

}

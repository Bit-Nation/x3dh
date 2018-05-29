package x3dh

type PreKeyBundle interface {
	IdentityKey() PublicKey
	SignedPreKey() PublicKey
	PreKeySignature() []byte
	OneTimePreKey() *PublicKey
	ValidSignature() bool
}

// ONLY FOR TESTING
type TestPreKeyBundle struct {
	identityKey     PublicKey
	signedPreKey    PublicKey
	preKeySignature []byte
	oneTimePreKey   *PublicKey
	validSignature  bool
}

func (b TestPreKeyBundle) IdentityKey() PublicKey {
	return b.identityKey
}

func (b TestPreKeyBundle) SignedPreKey() PublicKey {
	return b.signedPreKey
}

func (b TestPreKeyBundle) PreKeySignature() []byte {
	return b.preKeySignature
}

func (b TestPreKeyBundle) OneTimePreKey() *PublicKey {
	return b.oneTimePreKey
}

func (b TestPreKeyBundle) ValidSignature() bool {
	return b.validSignature
}

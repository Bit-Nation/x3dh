package x3dh

// the PreKeyBundle holds information
// about the person you would like to
// start chatting with. You need to implement
// this interface your self.
type PreKeyBundle interface {
	IdentityKey() PublicKey
	SignedPreKey() PublicKey
	PreKeySignature() []byte
	OneTimePreKey() *PublicKey
	// this is actually the method in which
	// you need to check if the signature
	// of the PreKey is valid. YOU HAVE
	// TO DO this your self. In case this
	// method returns false the process of
	// creating an shared secret will be aborted.
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

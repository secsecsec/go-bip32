package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// FirstHardenedChild is the index of the first child in the hardened range
	FirstHardenedChild = uint32(0x80000000)

	// SerializedKeyLength is the length of a serialized key in bytes
	SerializedKeyLength = 78
)

var (
	// PrivateWalletVersion is the version string to use for private wallets
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")

	// PublicWalletVersion is the version string to use for public wallets
	PublicWalletVersion, _ = hex.DecodeString("0488B21E")
)

var (
	ErrUnserializeInvalidLength = errors.New("Serialized keys must be exactly 78 bytes")
	ErrPublicKeyNotOnCurve      = errors.New("Public key does not exist on the secp256k1 curve")
	ErrPrivateKeyNoNULLByte     = errors.New("Private key has no NULL byte")
)

// Key is a bip32 extended key containing key data, chain code,
// parent information, and other meta data
type Key struct {
	Version     []byte // 4 bytes
	Depth       byte   // 1 byte
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	Key         []byte // 33 bytes
	IsPrivate   bool   // unserialized
}

// NewMasterKey creates a new master extended key from a seed
func NewMasterKey(seed []byte) (*Key, error) {
	// Generate key and chaincode
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	hmac.Write(seed)
	intermediary := hmac.Sum(nil)

	// Split it into our key and chain code
	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	// Validate key
	err := validatePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	// Create the key struct
	key := &Key{
		Version:     PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         keyBytes,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}

	return key, nil
}

// NewChildKey derives a child key from a given parent
func (key *Key) NewChildKey(childIdx uint32) (*Key, error) {
	hardenedChild := childIdx >= FirstHardenedChild
	childIndexBytes := uint32Bytes(childIdx)

	// Fail early if trying to create hardned child from public key
	if !key.IsPrivate && hardenedChild {
		return nil, errors.New("Can't create hardened child for public key")
	}

	// Get intermediary to create key and chaincode from.
	// Hardened children are based on the private key.
	// NonHardened children are based on the public key.
	var data []byte
	if hardenedChild {
		data = append([]byte{0x0}, key.Key...)
	} else {
		data = publicKeyForPrivateKey(key.Key)
	}
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, key.ChainCode)
	hmac.Write(data)
	intermediary := hmac.Sum(nil)

	// Create child Key with data common to both scenarios
	childKey := &Key{
		ChildNumber: childIndexBytes,
		ChainCode:   intermediary[32:],
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
	}

	// bip32 CKDpriv
	if key.IsPrivate {
		childKey.Version = PrivateWalletVersion
		childKey.FingerPrint = hash160(publicKeyForPrivateKey(key.Key))[:4]
		childKey.Key = addPrivateKeys(intermediary[:32], key.Key)

		// Validate key
		err := validatePrivateKey(childKey.Key)
		if err != nil {
			return nil, err
		}

		return childKey, nil
	}

	// bip32 CKDpub
	keyBytes := publicKeyForPrivateKey(intermediary[:32])

	// Validate key
	err := validateChildPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}

	childKey.Version = PublicWalletVersion
	childKey.FingerPrint = hash160(key.Key)[:4]
	childKey.Key = addPublicKeys(keyBytes, key.Key)

	return childKey, nil
}

// PublicKey creates a public version of key or returns a copy
// It is the 'Neuter' function from the bip32 spec
func (key *Key) PublicKey() *Key {
	keyBytes := key.Key

	if key.IsPrivate {
		keyBytes = publicKeyForPrivateKey(keyBytes)
	}

	return &Key{
		Version:     PublicWalletVersion,
		Key:         keyBytes,
		Depth:       key.Depth,
		ChildNumber: key.ChildNumber,
		FingerPrint: key.FingerPrint,
		ChainCode:   key.ChainCode,
		IsPrivate:   false,
	}
}

// Serialize serializes the Key into a 78 byte byte slice
func (key *Key) Serialize() []byte {
	// Private keys should be prepended with a single null byte
	keyBytes := key.Key
	if key.IsPrivate {
		keyBytes = append([]byte{0x0}, keyBytes...)
	}

	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	buffer.Write(key.Version)
	buffer.WriteByte(key.Depth)
	buffer.Write(key.FingerPrint)
	buffer.Write(key.ChildNumber)
	buffer.Write(key.ChainCode)
	buffer.Write(keyBytes)

	return buffer.Bytes()
}

// SerializeBase58 encodes the key as a serialized base58 string
func (key *Key) SerializeBase58() string {
	return base58Encode(key.Serialize())
}

func (key *Key) Unserialize(bytes []byte) error {
	// Validate length
	if len(bytes) != SerializedKeyLength {
		return ErrUnserializeInvalidLength
	}

	// Reconstruct Key
	key.Version = bytes[0:4]
	key.Depth = bytes[4]
	key.FingerPrint = bytes[5:9]
	key.ChildNumber = bytes[9:13]
	key.ChainCode = bytes[13:45]
	key.Key = bytes[45:78]

	// Handle private key. Set IsPrivate and remove NULL byte
	if bytesAreEqual(key.Version, PrivateWalletVersion) {
		key.IsPrivate = true

		if key.Key[0] != byte(0) {
			return ErrPrivateKeyNoNULLByte
		}

		key.Key = key.Key[1:]
	}

	// If it's a private key we're done
	if !bytesAreEqual(key.Version, PublicWalletVersion) {
		key.IsPrivate = true
		return nil
	}

	// Validate public key exists on curve
	if !curve.IsOnCurve(expandPublicKey(key.Key)) {
		fmt.Println("key:", key.Key)
		fmt.Println(expandPublicKey(key.Key))
		return ErrPublicKeyNotOnCurve
	}

	return nil
}

func UnserializeBase58(encoded string) (*Key, error) {
	bytes, err := base58Decode(encoded)
	if err != nil {
		return nil, err
	}

	key := &Key{}
	err = key.Unserialize(bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// String implements the Stringer interface by returning SerializeBase58
func (key *Key) String() string {
	return key.SerializeBase58()
}

// NewSeed creates a 256 byte slice of cryptographically random data
func NewSeed() ([]byte, error) {
	s := make([]byte, 256)
	_, err := rand.Read([]byte(s))
	return s, err
}

package main

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/bech32"
)

// TestPrivateKeyToPublicKey 测试从私钥生成公钥
func TestPrivateKeyToPublicKey(t *testing.T) {
	// 已知的私钥
	privateKeyHex := "90368805bc29fd028985e708572d644c9968eac49ec8bb7064b7851d3250f438"
	// 期望的公钥（base64）
	expectedPubKey := "A1oc7W+hrF9Nwv/9Ed+Qs2jUMDHzciEYkdKGNWRkvPm9"

	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	privKey := &secp256k1.PrivKey{Key: privKeyBytes}
	pubKey := privKey.PubKey().(*secp256k1.PubKey)
	actualPubKey := base64.StdEncoding.EncodeToString(pubKey.Bytes())

	if actualPubKey != expectedPubKey {
		t.Errorf("Public key mismatch\nExpected: %s\nActual:   %s", expectedPubKey, actualPubKey)
	} else {
		t.Logf("✓ Public key matches: %s", actualPubKey)
	}
}

// TestCosmosAddressDerivation 测试 Cosmos 标准地址推导
func TestCosmosAddressDerivation(t *testing.T) {
	privateKeyHex := "fcef6aa4b7286575573ff263eae5b38ce651e37832bc8d947d81302e61991a4e"
	expectedCosmosAddr := "me18qm2epjzyj674x8wej4g7t4mkdjgt9m85jnejt"

	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey := &secp256k1.PrivKey{Key: privKeyBytes}
	pubKey := privKey.PubKey().(*secp256k1.PubKey)

	// Cosmos 标准方式：SHA256 + RIPEMD160
	pubKeyAddr := pubKey.Address()
	address, err := bech32.ConvertAndEncode("me", pubKeyAddr)
	if err != nil {
		t.Fatalf("Failed to encode address: %v", err)
	}

	if address != expectedCosmosAddr {
		t.Errorf("Cosmos address mismatch\nExpected: %s\nActual:   %s", expectedCosmosAddr, address)
	} else {
		t.Logf("✓ Cosmos address matches: %s", address)
	}
}

// TestEthermintAddressDerivation 测试 Ethermint 地址推导
func TestEthermintAddressDerivation(t *testing.T) {
	privateKeyHex := "fcef6aa4b7286575573ff263eae5b38ce651e37832bc8d947d81302e61991a4e"
	expectedEthermintAddr := "me1j92wsc65k622ucnj7ux2h0cg3jjksgvs4s8rfa"

	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey := &secp256k1.PrivKey{Key: privKeyBytes}
	pubKey := privKey.PubKey().(*secp256k1.PubKey)

	// Ethermint 方式：Keccak256
	ethAddr := calculateEthAddress(pubKey.Bytes())
	address, err := bech32.ConvertAndEncode("me", ethAddr)
	if err != nil {
		t.Fatalf("Failed to encode address: %v", err)
	}

	if address != expectedEthermintAddr {
		t.Errorf("Ethermint address mismatch\nExpected: %s\nActual:   %s", expectedEthermintAddr, address)
	} else {
		t.Logf("✓ Ethermint address matches: %s", address)
	}
}

func BenchmarkEthermintAddressDerivation(b *testing.B) {
	privateKeyHex := "fcef6aa4b7286575573ff263eae5b38ce651e37832bc8d947d81302e61991a4e"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey := &secp256k1.PrivKey{Key: privKeyBytes}
	pubKey := privKey.PubKey().(*secp256k1.PubKey)
	pubKeyBytes := pubKey.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ethAddr := calculateEthAddress(pubKeyBytes)
		_, _ = bech32.ConvertAndEncode("me", ethAddr)
	}
}

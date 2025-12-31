package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"golang.org/x/crypto/sha3"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkTx "github.com/cosmos/cosmos-sdk/types/tx" // Import the tx package for transaction types
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authTypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/gogoproto/proto"
	ibctypes "github.com/cosmos/ibc-go/v10/modules/apps/transfer/types" // Import the IBC transfer types
)

func decodeTx() {
	// read the JSON file
	data, err := os.ReadFile("./tx.json")
	if err != nil {
		panic(err)
	}
	type TxJson struct {
		AuthInfoBytes string   `json:"auth_info_bytes"`
		BodyBytes     string   `json:"body_bytes"`
		Signatures    []string `json:"signatures"`
	}
	// analyze the JSON structure
	var tx TxJson
	if err = json.Unmarshal(data, &tx); err != nil {
		panic(err)
	}
	// analyze the transaction
	bodyBytes, _ := base64.StdEncoding.DecodeString(tx.BodyBytes)
	var body sdkTx.TxBody
	if err := proto.Unmarshal(bodyBytes, &body); err != nil {
		panic(err)
	}

	for _, anyMsg := range body.Messages {
		switch anyMsg.TypeUrl {
		case "/cosmos.bank.v1beta1.MsgSend":
			var msg types.MsgSend
			_ = proto.Unmarshal(anyMsg.Value, &msg)
			fmt.Printf("MsgSend: %+v\n", msg)
		case "/ibc.applications.transfer.v1.MsgTransfer":
			var msg ibctypes.MsgTransfer
			_ = proto.Unmarshal(anyMsg.Value, &msg)
			fmt.Printf("MsgTransfer: %+v\n", msg)
		default:
			fmt.Printf("Unknown msg type: %s\n", anyMsg.TypeUrl)
		}
	}

	// analyze auth_info_bytes
	authInfoBytes, _ := base64.StdEncoding.DecodeString(tx.AuthInfoBytes)
	var authInfo sdkTx.AuthInfo
	if err := proto.Unmarshal(authInfoBytes, &authInfo); err != nil {
		panic(err)
	}
	fmt.Printf("AuthInfo: %+v\n", authInfo)

	// analyze the signatures
	sigs := make([][]byte, len(tx.Signatures))
	for i, s := range tx.Signatures {
		sigs[i], _ = base64.StdEncoding.DecodeString(s)
		fmt.Printf("Signature %d: %x\n", i, sigs[i])
	}
	// create a new transaction
	tx2 := &sdkTx.Tx{
		AuthInfo:   &authInfo,
		Body:       &body,
		Signatures: sigs,
	}
	CallGRPCSimulate(tx2)
	// protobuf serialize the transaction
	txBytes, _ := proto.Marshal(tx2)
	fmt.Println("txBytes base64:", base64.StdEncoding.EncodeToString(txBytes))
	// calculate hash
	hash := sha256.Sum256(txBytes)
	fmt.Println("Tx Hash:", strings.ToUpper(hex.EncodeToString(hash[:])))
}
func CallGRPCSimulate(tx *sdkTx.Tx) {
	txBytes, err := proto.Marshal(tx)
	if err != nil {
		panic(err)
	}
	resp, err := client.Simulate(context.Background(), &sdkTx.SimulateRequest{
		TxBytes: txBytes,
	})
	if err != nil {
		fmt.Println("Simulate err:", err.Error())
		return
	}
	fmt.Println("Simulate Response:", resp)
}

func decodeTx2() {
	txs := "CkkKRwoXL2dlYS5jaGVja2luLk1zZ0NoZWNrSW4SLAoqZ2VhMWd1N2FlN3BqcHJxcDI3amtwNTd6bmhua3A0Njc1bDR6Z3k1MHYwElgKUApGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQJyjLM3xCd5LZuDMkrobCz7yrPC8TDZrLCgOXAKBtIBUhIECgIIARgfEgQQwJoMGkDGarGU/PgZLKxeHbdnBUVVX/NnEY1DYNCSKv29z7dhXhy7J/P8bHPfhYpZxDSjyyj+dJuBWUUawWrOO8h6adxt"
	txsBase64 := strings.Split(txs, ",")
	for i, txBase64 := range txsBase64 {
		txBase64 = strings.TrimPrefix(txBase64, "\n")
		txBase64 = strings.TrimPrefix(txBase64, " ")
		txBytes, err := base64.StdEncoding.DecodeString(txBase64)
		if err != nil {
			fmt.Println("err", err.Error())
		}
		hash := sha256.Sum256(txBytes)
		fmt.Println("Tx Hash:", strings.ToUpper(hex.EncodeToString(hash[:])))

		var tx sdkTx.Tx
		if err := proto.Unmarshal(txBytes, &tx); err != nil {
			panic(err)
		}
		CallGRPCSimulate(&tx)
		for _, anyMsg := range tx.Body.Messages {
			switch anyMsg.TypeUrl {
			case "/cosmos.bank.v1beta1.MsgSend":
				var msg types.MsgSend
				_ = proto.Unmarshal(anyMsg.Value, &msg)
				fmt.Printf("MsgSend: %+v\n", msg)
			default:
				fmt.Printf("Unknown msg type: %s\n", anyMsg.TypeUrl)
			}
		}
		// analyze public keys for each signer
		for i, signerInfo := range tx.AuthInfo.SignerInfos {
			fmt.Printf("Signer %d:\n", i)
			fmt.Printf("  Public Key Type: %s\n", signerInfo.PublicKey.TypeUrl)

			// analyze the public key
			if signerInfo.PublicKey.TypeUrl == "/cosmos.crypto.secp256k1.PubKey" {
				if len(signerInfo.PublicKey.Value) >= 35 {
					pubKeyBytes := signerInfo.PublicKey.Value[2:] // Skip the first two bytes (0x02 or 0x03)
					fmt.Printf("  Public Key (hex): %x\n", pubKeyBytes)
					pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)
					fmt.Printf("公钥（Base64）: %s\n", pubKeyBase64)
				}
			}

			fmt.Printf("  Sign Mode: %s\n", signerInfo.ModeInfo.GetSingle().Mode)
		}

		// show the fee information
		if tx.AuthInfo.Fee != nil {
			fmt.Printf("Fee: %+v\n", tx.AuthInfo.Fee)
			fmt.Printf("Gas Limit: %d\n", tx.AuthInfo.Fee.GasLimit)
		}
		fmt.Printf("AuthInfo: %+v\n", tx.AuthInfo)
		// analyze the signatures
		sigs := make([][]byte, len(tx.Signatures))
		for j, _ := range tx.Signatures {
			fmt.Printf("Signature %d: %x\n", j, sigs[j])
		}
		fmt.Println("---------------------------------- :", i)
	}
}
func GenerateKeyAndAddress(isCreate bool) (privKey *secp256k1.PrivKey, pubKey *secp256k1.PubKey, address string) {
	if isCreate {
		privateKeyBytes := make([]byte, 32)
		_, err := rand.Read(privateKeyBytes)
		if err != nil {
			fmt.Println("Error generating private key:", err)
			return
		}
		privKey = &secp256k1.PrivKey{Key: privateKeyBytes}
	} else {
		//Private Key:
		//Expected public Key: A1oc7W+hrF9Nwv/9Ed+Qs2jUMDHzciEYkdKGNWRkvPm9
		//Expected address: me1j92wsc65k622ucnj7ux2h0cg3jjksgvs4s8rfa
		privateKeyHex := "90368805bc29fd028985e708572d644c9968eac49ec8bb7064b7851d3250f438"
		privKeyBytes, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			fmt.Println("Error decoding private key:", err)
			return
		}
		privKey = &secp256k1.PrivKey{Key: privKeyBytes}
	}

	// 获取公钥
	pubKey = privKey.PubKey().(*secp256k1.PubKey)

	// 调试信息：打印原始公钥字节（33字节压缩格式）
	fmt.Printf("\n=== 密钥信息 ===\n")
	fmt.Printf("Private Key (hex): %x\n", privKey.Key)
	fmt.Printf("Private Key length: %d bytes\n", len(privKey.Key))

	// 公钥信息
	pubKeyBytes := pubKey.Bytes()
	fmt.Printf("\nPublic Key (hex): %x\n", pubKeyBytes)
	fmt.Printf("Public Key length: %d bytes\n", len(pubKeyBytes))
	fmt.Printf("Public Key (base64): %s\n", base64.StdEncoding.EncodeToString(pubKeyBytes))
	fmt.Printf("Public Key prefix: 0x%02x (0x02=even Y, 0x03=odd Y)\n", pubKeyBytes[0])
	fmt.Printf("Public Key Type: /ethermint.crypto.v1.ethsecp256k1.PubKey\n")

	// 方法1: Cosmos SDK 标准方式 (SHA256 + RIPEMD160)
	pubKeyAddr := pubKey.Address()
	fmt.Printf("\n=== Cosmos SDK 标准方式 ===\n")
	fmt.Printf("Address (raw bytes): %x\n", pubKeyAddr)
	fmt.Printf("Address length: %d bytes\n", len(pubKeyAddr))
	hash := sha256.Sum256(pubKeyBytes)
	fmt.Printf("SHA256(pubkey)[:20]: %x\n", hash[:20])

	addr := sdk.AccAddress(pubKeyAddr)
	address, err := bech32.ConvertAndEncode("me", addr)
	if err != nil {
		fmt.Println("Error converting address:", err)
		return
	}
	fmt.Printf("Bech32 Address (Cosmos): %s\n", address)

	// 方法2: Ethereum/Ethermint 方式 (Keccak256)
	fmt.Printf("\n=== Ethereum/Ethermint 方式 ===\n")
	// 需要使用未压缩的公钥 (65字节: 0x04 + 32字节X + 32字节Y)
	// 从压缩公钥恢复未压缩公钥，然后使用 Keccak256 计算地址
	ethAddr := calculateEthAddress(pubKeyBytes)
	fmt.Printf("ETH Address (raw bytes): %x\n", ethAddr)
	fmt.Printf("ETH Address length: %d bytes\n", len(ethAddr))

	ethAddrBech32, err := bech32.ConvertAndEncode("me", ethAddr)
	if err != nil {
		fmt.Println("Error converting eth address:", err)
		return
	}
	fmt.Printf("Bech32 Address (Ethermint): %s\n", ethAddrBech32)
	fmt.Printf("Expected Address: me1j92wsc65k622ucnj7ux2h0cg3jjksgvs4s8rfa\n")
	fmt.Printf("===================\n\n")

	// 返回 Ethermint 风格的地址
	return privKey, pubKey, ethAddrBech32
}

// calculateEthAddress 计算 Ethereum 风格的地址（Keccak256）
func calculateEthAddress(compressedPubKey []byte) []byte {
	// 从压缩公钥获取未压缩公钥
	// 压缩公钥格式: 0x02/0x03 + 32字节X坐标
	// 未压缩公钥格式: 0x04 + 32字节X + 32字节Y

	// 使用 btcec 库来扩展压缩公钥
	pubKey, err := btcec.ParsePubKey(compressedPubKey)
	if err != nil {
		fmt.Println("Error parsing compressed pubkey:", err)
		return nil
	}

	// 获取未压缩公钥（去掉0x04前缀）
	uncompressedPubKey := pubKey.SerializeUncompressed()[1:] // 跳过0x04前缀

	// 计算 Keccak256 哈希
	hash := sha3.NewLegacyKeccak256()
	hash.Write(uncompressedPubKey)
	fullHash := hash.Sum(nil)

	// 取后20字节作为地址
	return fullHash[12:]
}
func getAccountInfo(address string) (accountNumber uint64, sequence uint64, err error) {
	authClient := authTypes.NewQueryClient(conn)
	resp, err := authClient.Account(context.Background(), &authTypes.QueryAccountRequest{
		Address: address,
	})
	if err != nil {
		fmt.Println("Error getting account info:", err)
		return
	}
	var baseAccount authTypes.BaseAccount
	err = proto.Unmarshal(resp.Account.Value, &baseAccount)
	if err != nil {
		fmt.Println("Error unmarshalling BaseAccount:", err)
		return 0, 0, err
	}
	return baseAccount.AccountNumber, baseAccount.Sequence, nil
}
func MakeSendTx() {
	//1.create private key
	privKey, pubKey, address := GenerateKeyAndAddress(false)
	//2. Create a MsgSend message
	msgSend := &types.MsgSend{
		FromAddress: address,
		ToAddress:   address,
		Amount:      sdk.NewCoins(sdk.NewCoin("umec", math.NewInt(100))),
	}
	accountNumber, sequence, err := getAccountInfo(address)
	if err != nil {
		fmt.Println("Error getting account info:", err)
		return
	}
	//3. Create an Any type to hold the MsgSend message
	msgSendAny, err := codectypes.NewAnyWithValue(msgSend)
	if err != nil {
		fmt.Println("Error creating Any with MsgSend:", err)
		return
	}
	//4. Create a TxBody with the MsgSend message
	txBody := &sdkTx.TxBody{
		Messages:      []*codectypes.Any{msgSendAny},
		Memo:          "Test transaction",
		TimeoutHeight: 0,
	}
	//5. Create an Any type to hold the public key
	pubKeyAny, err := codectypes.NewAnyWithValue(pubKey)
	if err != nil {
		fmt.Println("Error creating Any with PubKey:", err)
		return
	}

	//6.create signer info
	signerInfo := &sdkTx.SignerInfo{
		PublicKey: pubKeyAny,
		ModeInfo: &sdkTx.ModeInfo{
			Sum: &sdkTx.ModeInfo_Single_{
				Single: &sdkTx.ModeInfo_Single{
					Mode: signing.SignMode_SIGN_MODE_DIRECT,
				},
			},
		},
		Sequence: sequence,
	}
	//7. create fee
	fee := &sdkTx.Fee{
		Amount:   sdk.NewCoins(sdk.NewCoin("umec", math.NewInt(10000))),
		GasLimit: 500000,
	}
	//8.create auth info
	authInfo := &sdkTx.AuthInfo{
		SignerInfos: []*sdkTx.SignerInfo{signerInfo},
		Fee:         fee,
	}
	// ======create sign(if simulate, no need to sign)=======

	//9. serialize txBody
	bodyBytes, err := proto.Marshal(txBody)
	if err != nil {
		fmt.Println("Error marshalling txBody:", err)
		return
	}
	//10.serialize authInfo
	authInfoBytes, err := proto.Marshal(authInfo)
	if err != nil {
		fmt.Println("Error marshalling authInfo:", err)
		return
	}
	//11. Create a SignDoc for signing
	signDoc := &sdkTx.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainId:       "mechain_400-1",
		AccountNumber: accountNumber,
	}
	signBytes, err := proto.Marshal(signDoc)
	if err != nil {
		fmt.Println("Error marshalling signDoc:", err)
		return
	}
	signatures, err := privKey.Sign(signBytes)
	if err != nil {
		fmt.Println("Error signing signDoc:", err)
		return
	}

	//12.create transaction
	tx := &sdkTx.Tx{
		Body:       txBody,
		AuthInfo:   authInfo,
		Signatures: [][]byte{signatures},
	}
	txBytes, err := proto.Marshal(tx)
	if err != nil {
		fmt.Println("Error marshalling tx:", err)
		return
	}
	fmt.Println("Transaction Bytes (Base64):", base64.StdEncoding.EncodeToString(txBytes))

	// 13. simulate the transaction using gRPC
	CallGRPCSimulate(tx)

	// 14. calculate the transaction hash
	hash := sha256.Sum256(txBytes)
	fmt.Printf("交易哈希: %s\n", strings.ToUpper(hex.EncodeToString(hash[:])))
	//15. broadcast the transaction
	broadcastResp, err := client.BroadcastTx(context.Background(), &sdkTx.BroadcastTxRequest{
		TxBytes: txBytes,
		Mode:    sdkTx.BroadcastMode_BROADCAST_MODE_SYNC, // or use BROADCAST_MODE_ASYNC, BROADCAST_MODE_BLOCK
	})
	if err != nil {
		fmt.Println("Broadcast error:", err)
		return
	}
	fmt.Printf("Broadcast Response: %+v\n", broadcastResp)
	fmt.Printf("Transaction Hash: %s\n", broadcastResp.TxResponse.TxHash)
}
func SendTxBytes() {
	// Example transaction bytes (replace with actual transaction bytes)
	txBytes := "CogKCpoBCikvbWV0YWVhcnRoLndzdGFraW5nLk1zZ1dpdGhkcmF3RnJvbVJlZ2lvbhJtCiltZTFoZDV5OWhlcGprYzIyZXdhcXVsZGNqcWVsbHBuMjhrNGR4ejVhbBIDcnVzGiltZTF6N3NmM2g4cnd2dnU2OWd5bG16dGRmc3gwbDN1enRkdW01OXA0aCIQCgR1bWVjEggyMDA0MDAwMAqaAQopL21ldGFlYXJ0aC53c3Rha2luZy5Nc2dXaXRoZHJhd0Zyb21SZWdpb24SbQopbWUxaGQ1eTloZXBqa2MyMmV3YXF1bGRjanFlbGxwbjI4azRkeHo1YWwSA2FyZRopbWUxcmRjM3lmNmxkczN2MHZyM2Y2N3R1Z3hqeG04azloNTd3dnhhZ2ciEAoEdW1lYxIIODAwNDAwMDAKmgEKKS9tZXRhZWFydGgud3N0YWtpbmcuTXNnV2l0aGRyYXdGcm9tUmVnaW9uEm0KKW1lMWhkNXk5aGVwamtjMjJld2FxdWxkY2pxZWxscG4yOGs0ZHh6NWFsEgNteXMaKW1lMTU3ZndnZnJnbnE2Z3FqNTBqMmZ6cDhlY2dmcjI0MzNsMDVrN2NkIhAKBHVtZWMSCDEwMDQwMDAwCpoBCikvbWV0YWVhcnRoLndzdGFraW5nLk1zZ1dpdGhkcmF3RnJvbVJlZ2lvbhJtCiltZTFoZDV5OWhlcGprYzIyZXdhcXVsZGNqcWVsbHBuMjhrNGR4ejVhbBIDYW5kGiltZTFuZDgyN21sbjM3a3djcnVsN3gzeXdwbWs4ank3ZGhrNmE2a2o3eiIQCgR1bWVjEgg2MDA0MDAwMAqbAQopL21ldGFlYXJ0aC53c3Rha2luZy5Nc2dXaXRoZHJhd0Zyb21SZWdpb24SbgopbWUxaGQ1eTloZXBqa2MyMmV3YXF1bGRjanFlbGxwbjI4azRkeHo1YWwSA2NobhopbWUxajRqY3J3YXl4N3JmemdsenZrMzA0ODc0ZHduNTV2OWxhdHE3NHYiEQoEdW1lYxIJMTMwMDQwMDAwCpoBCikvbWV0YWVhcnRoLndzdGFraW5nLk1zZ1dpdGhkcmF3RnJvbVJlZ2lvbhJtCiltZTFoZDV5OWhlcGprYzIyZXdhcXVsZGNqcWVsbHBuMjhrNGR4ejVhbBIDdGhhGiltZTFtc3N6bHYzMDY1Z2tmY2YydDZzMzQwMDU1bW05aGZ4cXBneGhycCIQCgR1bWVjEggxMDA0MDAwMAqfAQopL21ldGFlYXJ0aC53c3Rha2luZy5Nc2dXaXRoZHJhd0Zyb21SZWdpb24ScgopbWUxaGQ1eTloZXBqa2MyMmV3YXF1bGRjanFlbGxwbjI4azRkeHo1YWwSCG1lX2VhcnRoGiltZTF2Z2ttdHNnOTZmNm56cDAwcTRsa3NjcHhwZm00bmZ4eXFuczd5eCIQCgR1bWVjEgg2MDA0MDAwMAqaAQopL21ldGFlYXJ0aC53c3Rha2luZy5Nc2dXaXRoZHJhd0Zyb21SZWdpb24SbQopbWUxaGQ1eTloZXBqa2MyMmV3YXF1bGRjanFlbGxwbjI4azRkeHo1YWwSA2F1cxopbWUxeTY4OW56aHc4djU0OXR6NmpjdTNnc3dzZ2Y0ZTZ2OXB0cTNzbDgiEAoEdW1lYxIIMTAwNDAwMDASGENvbW11bml0eSBHcm93dGggUmV3YXJkcxLVBArLBAqoBAopL2Nvc21vcy5jcnlwdG8ubXVsdGlzaWcuTGVnYWN5QW1pbm9QdWJLZXkS+gMIAxJGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQIKS0HHqkfgTJ7lmNcogtlDTCohmfArtb46oaanHp5YeBJGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQOVqXiO3NzDbYI/MUXnoDyjlQG/CChcRxXGg7Iblm86JBJGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQNxGuXFf3CIOrztn/fnwQ/mGdUTs2ia5EugCxGBnZ7wGhJGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQNEzCzl4xJJe5GQ70BMFAeBM+Zu200Wx+ZoE2fA4cm+UBJGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQOgkrTA+QrmotXx6QmQiKMuymkOMrmUUazbaIyY9Iz9uxJGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQKHHsZ+eVZfJrhAw76u5PKJm/pZZGvt4XX/Nt+DcEnXvRJGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQMWSMuOfMKmrdJXnbgA1B9dmjGg/X8K3WuwY2pRhqTDwBIbEhkKBQgHEgGUEgQKAgh/EgQKAgh/EgQKAgh/GN4DEgUQgJL0ARrGAQpAmxN6M9nCUgQlalqwS1bKoFaLll018UI+ehD1Ido7Gu9Q1cBXGOKBSGOHCWkhQlBEuGG6LMoLQMHa4m3YG3Ay5wpADXtf3HEom0bQXY+iw2jHhN1fDavVHRdzQ8ILAeIcNK0+GouC2Vmam2eYT8evrrqGLOCDxc1qKE/Q+kHl/UJWogpAydKC4iCR4lnNcPYD+PgBuC54370HN4w1mgk82IwD8rM0cyss0319GiRVDhD/J35TMMHdu/P8ZjMe/omuLiw3xA=="
	txBytesDecoded, err := base64.StdEncoding.DecodeString(txBytes)
	if err != nil {
		fmt.Println("Error decoding transaction bytes:", err)
		return
	}
	fmt.Println("Decoded Transaction Bytes:", txBytesDecoded)
	// Call the gRPC Simulate method with the decoded transaction bytes
	//CallGRPCSimulate(&sdkTx.Tx{Body: &sdkTx.TxBody{Messages: []*codectypes.Any{{TypeUrl: "/cosmos.bank.v1beta1.MsgSend", Value: txBytesDecoded}}}})

	broadcastResp, err := client.BroadcastTx(context.Background(), &sdkTx.BroadcastTxRequest{
		TxBytes: txBytesDecoded,
		Mode:    sdkTx.BroadcastMode_BROADCAST_MODE_SYNC, // or use BROADCAST_MODE_ASYNC, BROADCAST_MODE_BLOCK
	})
	if err != nil {
		fmt.Println("Broadcast error:", err)
		return
	}
	fmt.Printf("Broadcast Response: %+v\n", broadcastResp)
	fmt.Printf("Transaction Hash: %s\n", broadcastResp.TxResponse.TxHash)
}

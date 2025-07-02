package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"math/rand"
	"os"
	"strings"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkTx "github.com/cosmos/cosmos-sdk/types/tx" // Import the tx package for transaction types
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/gogoproto/proto"
)

/*
// Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
//select the grpc server interface list
grpcurl -plaintext localhost:9090 list
//select the grpc server interface method
grpcurl -plaintext localhost:9090 cosmos.tx.v1beta1.Service/Simulate
//select the grpc server interface method parameters
grpcurl -plaintext localhost:9090 describe cosmos.bank.v1beta1.Query.Balance
// Example command to simulate a transaction using grpcurl
grpcurl -plaintext -d '{"tx_bytes":"CooBCocBChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEmcKKW1lMXc3anF1eDdzOXF5ZzJ4d2YzOXVtbmFoZjhsNzcyZXd5MmR3ZnQ1EiltZTFkdmx4d3J4OWdqbjdxMGFnNGpjbGo2N2doN214dTk0NDM5Z3NhZxoPCgR1bWVjEgcxMjY5OTkzEmUKTgpGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQIsk7sSnmNf6ZBiDJa/eSnnG2YJj7uxABQp1gi3QQPcrBIECgIIARITCg0KBHVtZWMSBTEwMDAwEKDCHhpAXznezZ6aLYDbOrUOegFwVoUP5AjzP220ojQf+Nnnui55YlCi97Fir7sH+H/CrtqlzbaMCaQOYUP7MjtoEeE7ng=="}' 192.168.0.84:9090 cosmos.tx.v1beta1.Service/Simulate
*/
var (
	client sdkTx.ServiceClient
	conn   *grpc.ClientConn
)

func init() {
	var err error
	//connect gRpc server
	conn, err = grpc.NewClient("192.168.0.84:19090", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	//create a grpc client
	client = sdkTx.NewServiceClient(conn)
}
func main() {
	//decodeTx2()
	//decodeTx()
	MakeSendTx()
	err := conn.Close()
	if err != nil {
		fmt.Println("Error closing connection:", err)
	}
}
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
	txs := "CosBCogBChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEmgKKW1lMTI0ejMyZ2ZwdnE3OXdycno2YXhoaGRhZmVuMHp3endqZmp4ZTI3EiltZTFyM3h1ZWhhajQ1eDBjemszM2N4ajlsa3AzamN5bWFuOHZleTUzMBoQCgR1bWVjEggyNTUwMDAwMBJoClEKRgofL2Nvc21vcy5jcnlwdG8uc2VjcDI1NmsxLlB1YktleRIjCiECBpaZ+tOtXfdMaI7WX45R3WVcwpEkfyiOdT/4K1I059kSBAoCCAEY0gISEwoNCgR1bWVjEgUxMzIzMRCgwh4aQNZ6EUbG5+5KTkVHTmPCLxhcQioywwvpDIhQqxKKJAAUfKEjuT7BPytWlAlks2IwcwTlmcs/nOKmhuowcGIUaHo="
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
		//public Key: Agr366jFJ6kpvg9/yHAmprFMAydBn0sso0fzyCfUuRLd
		//address: me1vxekpa9gsktfdeydqn4vh3jyt7hwafpmkmfqdd
		privateKeyHex := ""
		privKeyBytes, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			fmt.Println("Error decoding private key:", err)
			return
		}
		privKey = &secp256k1.PrivKey{Key: privKeyBytes}
	}
	pubKey = privKey.PubKey().(*secp256k1.PubKey)
	addr := sdk.AccAddress(pubKey.Address())
	address, err := bech32.ConvertAndEncode("me", addr)
	if err != nil {
		fmt.Println("Error converting address:", err)
		return
	}
	fmt.Printf("Private Key: %x\n", privKey.Key)
	fmt.Printf("public Key: %s\n", base64.StdEncoding.EncodeToString(pubKey.Bytes()))
	fmt.Printf("address: %s\n", address)
	return privKey, pubKey, address
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
		Sequence: 1,
	}
	//7. create fee
	fee := &sdkTx.Fee{
		Amount:   sdk.NewCoins(sdk.NewCoin("umec", math.NewInt(3058))),
		GasLimit: 100000,
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
		ChainId:       "me-chain",
		AccountNumber: 1370046,
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

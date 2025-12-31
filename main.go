package main

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	sdkTx "github.com/cosmos/cosmos-sdk/types/tx" // Import the tx package for transaction types
	// Import the IBC transfer types
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
	//xxx.xxx.0.248:9290  gea uat rollapp
	//xxx.xx.0.230:9290  me uat rollapp
	//xxx.xxx.0.230:9090 me uat hub
	conn, err = grpc.NewClient("118.175.0.249:9090", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	//create a grpc client
	client = sdkTx.NewServiceClient(conn)
}
func main() {
	//decodeTx2()
	//decodeTx()
	// GenerateKeyAndAddress(false)
	MakeSendTx()
	//SendTxBytes()
	err := conn.Close()
	if err != nil {
		fmt.Println("Error closing connection:", err)
	}
}

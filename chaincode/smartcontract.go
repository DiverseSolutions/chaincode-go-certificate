package chaincode

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing a Certificate
type SmartContract struct {
	contractapi.Contract
}

func (s *SmartContract) GetName() string {
	return "certificate"
}

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {

	return nil
}

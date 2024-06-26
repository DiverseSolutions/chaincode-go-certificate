package chaincode

import (
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (s *SmartContract) NewCertificateStateId(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	_, err := uuid.Parse(id)
	if err != nil {
		return "", err
	}
	return ctx.GetStub().CreateCompositeKey("Certificate", []string{id})
}

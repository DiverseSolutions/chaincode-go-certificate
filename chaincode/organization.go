package chaincode

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type Organization struct {
	DocType           string `json:"docType"`
	ID                string `json:"id"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	InstitutionID     string `json:"institutionId"`
	InstitutionName   string `json:"institutionName"`
	Desc              string `json:"desc"`
	OrgCreditID       string `json:"orgCreditId"`
	LogoUrl           string `json:"logoUrl"`
	IsActive          bool   `json:"isActive"`
	PubKeyType        string `json:"pubKeyType"`
	PubKeyPem         string `json:"pubKeyPem"`
	CreateTxTimestamp int64  `json:"createTxTimestamp"`
	UpdateTxTimestamp int64  `json:"updateTxTimestamp"`
}

func (s *SmartContract) ReadMyOrg(ctx contractapi.TransactionContextInterface) (*Organization, error) {
	resp := ctx.GetStub().InvokeChaincode("organization", [][]byte{[]byte("ReadMyOrg")}, ctx.GetStub().GetChannelID())
	if resp.Status == shim.ERROR {
		return nil, fmt.Errorf(resp.Message)
	}
	var org Organization
	err := json.Unmarshal(resp.Payload, &org)
	if err != nil {
		return nil, err
	}
	return &org, nil
}

func (s *SmartContract) ReadOrg(ctx contractapi.TransactionContextInterface, id string) (*Organization, error) {
	resp := ctx.GetStub().InvokeChaincode("organization", [][]byte{[]byte("ReadOrg"), []byte(id)}, ctx.GetStub().GetChannelID())
	if resp.Status == shim.ERROR {
		return nil, fmt.Errorf(resp.Message)
	}
	var org Organization
	err := json.Unmarshal(resp.Payload, &org)
	if err != nil {
		return nil, err
	}
	return &org, nil
}

package chaincode

import (
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type OrgCredit struct {
	DocType     string `json:"docType"`
	ID          string `json:"id"`
	OrgID       string `json:"orgId"`
	Amount      string `json:"amount"`
	TxTimestamp int64  `json:"txTimestamp"`
}

type OrgCreditLog struct {
	DocType     string `json:"docType"`
	ID          string `json:"id"`
	Title       string `json:"title"`
	OrgID       string `json:"orgId"`
	CreditID    string `json:"creditId"`
	Amount      string `json:"amount"`
	TxTimestamp int64  `json:"txTimestamp"`
}

func (s *SmartContract) spendOrgCredit(ctx contractapi.TransactionContextInterface, creditId, orgId, amount, title string) error {

	resp := ctx.GetStub().InvokeChaincode("organization", [][]byte{[]byte("SpendCredit"), []byte(creditId), []byte(orgId), []byte(amount), []byte(title)}, ctx.GetStub().GetChannelID())
	if resp.Status == shim.OK {
		return nil
	}
	return fmt.Errorf(resp.Message)
}

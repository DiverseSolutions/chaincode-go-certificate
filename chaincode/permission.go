package chaincode

import (
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (s *SmartContract) IsIdentitySuperAdmin(ctx contractapi.TransactionContextInterface) error {
	resp := ctx.GetStub().InvokeChaincode("organization", [][]byte{[]byte("IsIdentitySuperAdmin")}, ctx.GetStub().GetChannelID())
	if resp.Status == shim.OK {
		return nil
	}
	return fmt.Errorf(resp.Message)
}

func (s *SmartContract) IsIdentitySuperAdminOrHasAnyRoleOnOrg(ctx contractapi.TransactionContextInterface, orgId string) error {
	resp := ctx.GetStub().InvokeChaincode("organization", [][]byte{[]byte("IsIdentitySuperAdminOrHasAnyRoleOnOrg"), []byte(orgId)}, ctx.GetStub().GetChannelID())
	if resp.Status == shim.OK {
		return nil
	}
	return fmt.Errorf(resp.Message)
}

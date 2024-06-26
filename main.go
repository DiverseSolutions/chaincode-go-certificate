/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/diplom-mn/chaincode-go-certificate/chaincode"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	chaincode, err := contractapi.NewChaincode(&chaincode.SmartContract{})
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}

	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting chaincode: %v", err)
	}
}

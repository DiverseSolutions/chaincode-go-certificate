package chaincode

import "fmt"

func newPermissionDeniedError() error {
	return fmt.Errorf("Permission Denied")
}

func newInSufficientPermissionError() error {
	return fmt.Errorf("Insufficient Permission")
}

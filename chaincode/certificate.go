package chaincode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

var CERT_STATUS_NEW = "new"
var CERT_STATUS_VALID = "valid"
var CERT_STATUS_REVOKED = "revoked"

type Certificate struct {
	DocType           string                                        `json:"docType" validate:"required" validate:"required"` // "Certificate"
	ID                string                                        `json:"id" validate:"required"`
	TxId              string                                        `json:"txId" validate:"required"`
	OrgId             string                                        `json:"orgId" validate:"required"`
	Status            string                                        `json:"status" validate:"required"` // new | pending | valid | revoked
	ClaimsHash        string                                        `json:"claimsHash" validate:"required"`
	Claims            CertificateClaims                             `json:"claims" validate:"required"`
	SignOrgID         []string                                      `json:"signOrgID" validate:"required"`
	OrgSignatures     map[string]map[string]CertificateOrgSignature `json:"orgSignatures" validate:"required"`
	OrgSignProps      map[string][]OrgSignProp                      `json:"orgSignProps" validate:"required"`
	CreatedByOrg      string                                        `json:"createdByOrg" validate:"required"`
	ValidAt           int64                                         `json:"validAtTimestamp"`
	PendingAt         int64                                         `json:"pendingAtTimestamp"`
	RevokedAt         int64                                         `json:"revokedAtTimestamp"`
	CreateTxTimestamp int64                                         `json:"createTxTimestamp" validate:"required"`
}

type CertificateClaims struct {
	CertNumber      string                  `json:"certNumber" validate:"required"` // can be duplicated for each language
	Language        string                  `json:"language" validate:"required"`
	FirstName       string                  `json:"firstName" validate:"required"`
	LastName        string                  `json:"lastName" validate:"required"`
	Email           string                  `json:"email" validate:"required"`
	InstitutionName string                  `json:"institutionName" validate:"required"`
	Title           string                  `json:"title" validate:"required"`
	Description     string                  `json:"description" validate:"required"`
	IssuedOn        string                  `json:"issuedOn" validate:"required"`
	Extras          CertificateClaimsExtras `json:"extras" validate:"required"`
}

type CertificateClaimsExtras struct {
	AdditionalText []string       `json:"additionalText" validate:"omitempty"`
	Signer         []SignerPerson `json:"signer" validate:"omitempty"`
}

type CertificateOrgSignature struct {
	PubKeyType string `json:"pubKeyType" validate:"required"`
	PubKeyPem  string `json:"pubKeyPem" validate:"required"`
	Signature  string `json:"signature" validate:"required"`
}

type SignerPerson struct {
	Title string `json:"title" validate:"required"`
	Name  string `json:"name" validate:"required"`
}

type CertificateCreatedEventItem struct {
	ID        string   `json:"id" validate:"required"`
	SignOrgID []string `json:"signOrgID" validate:"required"`
}

type CertificateValidEventItem struct {
	ID        string   `json:"id" validate:"required"`
	SignOrgID []string `json:"signOrgID" validate:"required"`
}

type ListCertificate struct {
	BookMark string         `json:"bookMark" validate:"required"`
	Records  []*Certificate `json:"records" validate:"required"`
}

type CreateCertificateArg struct {
	ID           string                   `json:"id" validate:"required"`
	Claims       CertificateClaims        `json:"claims" validate:"required"`
	PubKeyType   string                   `json:"pubKeyType" validate:"required"`
	PubKeyPem    string                   `json:"pubKeyPem" validate:"required"`
	Signature    string                   `json:"signature" validate:"required"`
	SignOrgID    []string                 `json:"signOrgID" validate:"required"`
	OrgSignProps map[string][]OrgSignProp `json:"orgSignProps" validate:"required"`
}

type OrgSignProp struct {
	Key string `json:"key" validate:"required"`
}

type CreateCertificateBatchItem struct {
	Arg CreateCertificateArg `json:"arg" validate:"required"`
}

func (s *SmartContract) CreateCertificate(ctx contractapi.TransactionContextInterface, id string, createArg string) error {
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("ID err - %s", err)
	}
	org, err := s.ReadMyOrg(ctx)
	if err != nil {
		return err
	}

	if !org.IsActive {
		return fmt.Errorf("Organization is inactive - %s", org.ID)
	}

	txTimestamp, _ := ctx.GetStub().GetTxTimestamp()

	var ts int64
	if txTimestamp != nil {
		ts = txTimestamp.AsTime().Unix()
	}

	validate := validator.New()

	var cData CreateCertificateArg
	if err := json.Unmarshal([]byte(createArg), &cData); err != nil {
		return err
	}
	if err := validate.Struct(cData); err != nil {
		return fmt.Errorf("CreateArg invalid - %s", err)
	}

	exists, err := s.CertificateExists(ctx, id)

	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("%s already exists", id)
	}

	if len(cData.SignOrgID) < 1 {
		return fmt.Errorf("SignOrgID must be greater than or equal to 1")
	}

	for _, vo := range cData.SignOrgID {
		org, err := s.ReadOrg(ctx, vo)
		if err != nil {
			return err
		}
		if !org.IsActive {
			return fmt.Errorf("Org is inactive")
		}
	}

	signSelf := false
	for _, vo := range cData.SignOrgID {
		if vo == org.ID {
			signSelf = true
			break
		}
	}
	if !signSelf {
		return fmt.Errorf("SignOrgID is required to include your org")
	}

	signPropSelf := false
	for k := range cData.OrgSignProps {
		if k == org.ID {
			signPropSelf = true
			break
		}
	}
	if !signPropSelf {
		return fmt.Errorf("Signing property does not include org")
	}

	if _, err := time.Parse(time.RFC3339, cData.Claims.IssuedOn); err != nil {
		return fmt.Errorf("issuedOn format is invalid - %s", err)
	}

	if cData.Claims.Language != "MN" && cData.Claims.Language != "EN" {
		return fmt.Errorf("Unsupported Language")
	}

	if org.PubKeyPem != cData.PubKeyPem {
		return fmt.Errorf("Public key mismatch")
	}

	if org.PubKeyType != cData.PubKeyType {
		return fmt.Errorf("Public key type mismatch")
	}

	isSigValid, err := verifyClaimsSignature(cData.Claims, cData.PubKeyPem, cData.Signature)
	if err != nil {
		return err
	}
	if !isSigValid {
		return fmt.Errorf("Signature invalid")
	}

	cHash, _, err := NewCertificateClaimsHash(cData.Claims)
	if err != nil {
		return err
	}
	status := CERT_STATUS_NEW
	if len(cData.SignOrgID) == 1 && cData.SignOrgID[0] == org.ID {
		status = CERT_STATUS_VALID
	}

	cert := Certificate{
		DocType:      "Certificate",
		ID:           id,
		TxId:         ctx.GetStub().GetTxID(),
		OrgId:        org.ID,
		Status:       status,
		ClaimsHash:   cHash,
		Claims:       cData.Claims,
		SignOrgID:    cData.SignOrgID,
		OrgSignProps: cData.OrgSignProps,
		OrgSignatures: map[string]map[string]CertificateOrgSignature{
			org.ID: {
				cHash: {
					PubKeyType: cData.PubKeyType,
					PubKeyPem:  cData.PubKeyPem,
					Signature:  cData.Signature,
				},
			},
		},
		CreatedByOrg:      org.ID,
		ValidAt:           0,
		PendingAt:         0,
		RevokedAt:         0,
		CreateTxTimestamp: ts,
	}

	if err := validate.Struct(cert); err != nil {
		return fmt.Errorf("data invalid - %s", err)
	}

	certJSON, err := json.Marshal(cert)
	if err != nil {
		return err
	}

	stateId, err := s.NewCertificateStateId(ctx, id)
	if err != nil {
		return fmt.Errorf("id err - %s", err)
	}

	err = ctx.GetStub().PutState(stateId, certJSON)
	if err != nil {
		return err
	}

	s.spendOrgCredit(ctx, org.OrgCreditID, org.ID, "1", "Cost of creating a certificate")

	if status == CERT_STATUS_NEW {
		ei := CertificateCreatedEventItem{
			ID:        cert.ID,
			SignOrgID: cert.SignOrgID,
		}
		event := []CertificateCreatedEventItem{ei}
		eventJSON, err := json.Marshal(event)
		if err != nil {
			return err
		}
		err = ctx.GetStub().SetEvent("CertificateCreated", eventJSON)
		if err != nil {
			return err
		}
	} else if status == CERT_STATUS_VALID {
		ei := CertificateValidEventItem{
			ID:        cert.ID,
			SignOrgID: cert.SignOrgID,
		}
		event := []CertificateValidEventItem{ei}
		eventJSON, err := json.Marshal(event)
		if err != nil {
			return err
		}
		err = ctx.GetStub().SetEvent("CertificateValid", eventJSON)
		if err != nil {
			return err
		}
	}

	return nil
}

// batchArg - list of certificate json
func (s *SmartContract) CreateCertificateBatch(ctx contractapi.TransactionContextInterface, batchArg string) error {

	validate := validator.New()

	var createArgs []CreateCertificateBatchItem
	if err := json.Unmarshal([]byte(batchArg), &createArgs); err != nil {
		return err
	}

	event := make([]CertificateCreatedEventItem, len(createArgs))
	for _, arg := range createArgs {
		if err := validate.Struct(arg); err != nil {
			return fmt.Errorf("Invalid batch item - %s", err)
		}
		cda, err := json.Marshal(arg.Arg)
		if err != nil {
			return err
		}
		err = s.CreateCertificate(ctx, arg.Arg.ID, string(cda))
		if err != nil {
			return err
		}
		eventItem := CertificateCreatedEventItem{
			ID:        arg.Arg.ID,
			SignOrgID: arg.Arg.SignOrgID,
		}
		event = append(event, eventItem)
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}
	err = ctx.GetStub().SetEvent("CertificateCreated", eventJSON)
	if err != nil {
		return err
	}
	return nil
}

func (s *SmartContract) SignCertificate(ctx contractapi.TransactionContextInterface, id string, pubKeyType string, pubKeyPemArg string, signPropKeyArg string, hashArg string, signatureArg string) error {

	if pubKeyType != "ecdsa:P-384" {
		return fmt.Errorf("Unsupported Public key type")
	}

	pemBlock, _ := pem.Decode([]byte(pubKeyPemArg))
	pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return err
	}
	_, pubKeyOk := pubKey.(*ecdsa.PublicKey)
	if !pubKeyOk {
		return fmt.Errorf("Public key invalid")
	}

	validate := validator.New()

	c, err := s.ReadCertificate(ctx, id)
	if err := validate.Struct(c); err != nil {
		return fmt.Errorf("data invalid - %s", err)
	}

	org, err := s.ReadMyOrg(ctx)
	if err != nil {
		return err
	}

	perm := false
	for _, orgId := range c.SignOrgID {
		if orgId == org.ID {
			perm = true
			break
		}
	}
	if !perm {
		return newPermissionDeniedError()
	}

	if c.Status != CERT_STATUS_NEW {
		return fmt.Errorf("Certificate status is %s. Expected \"%s\"", c.Status, CERT_STATUS_NEW)
	}

	if c.ValidAt != 0 {
		return fmt.Errorf("Certificate has \"valid at\" timestamp")
	}

	if c.RevokedAt != 0 {
		return fmt.Errorf("Certificate has \"revoked at\" timestamp")
	}
	stateJSON, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(stateJSON, &m); err != nil {
		return err
	}

	signPropVals, ok := c.OrgSignProps[org.ID]
	if !ok {
		return fmt.Errorf("OrgSignProps does not contain org id")
	}
	signPropPerm := false
	for _, sp := range signPropVals {
		if sp.Key == signPropKeyArg {
			signPropPerm = true
			break
		}
	}
	if !signPropPerm {
		return fmt.Errorf("Signing property permission denied")
	}

	lookupKeys := strings.Split(signPropKeyArg, ".")
	val, err := NestedMapLookup(m, lookupKeys)
	if err != nil {
		return fmt.Errorf("Signing property does not exist")
	}
	valJSON, err := json.Marshal(val)
	if err != nil {
		return err
	}
	hashStr, hash, err := NewInterfaceHash(valJSON)
	if err != nil {
		return err
	}
	reqHashStr, _, err := NewStringHash(hashArg)
	if err != nil {
		return err
	}

	if hashStr != reqHashStr {
		return fmt.Errorf("Signing property hash does not match")
	}

	if org.PubKeyPem != pubKeyPemArg {
		return fmt.Errorf("Public key mismatch")
	}

	if org.PubKeyType != "ecdsa:P-384" {
		return fmt.Errorf("Public key type mismatch")
	}

	sigValid, err := verifySignature(hash, pubKeyPemArg, signatureArg)
	if err != nil {
		return err
	}
	if !sigValid {
		return fmt.Errorf("Signature invalid")
	}

	c.OrgSignatures[org.ID] = map[string]CertificateOrgSignature{
		hashStr: {
			PubKeyType: pubKeyType,
			PubKeyPem:  pubKeyPemArg,
			Signature:  signatureArg,
		},
	}

	isValid := true
	for _, o := range c.SignOrgID {
		_, ok := c.OrgSignatures[o]
		if !ok {
			isValid = false
			break
		}
	}
	if isValid {
		txTimestamp, _ := ctx.GetStub().GetTxTimestamp()

		var ts int64
		if txTimestamp != nil {
			ts = txTimestamp.AsTime().Unix()
		}
		c.Status = CERT_STATUS_VALID
		c.ValidAt = ts
	}
	updatedStateJSON, err := json.Marshal(c)
	stateId, err := s.NewCertificateStateId(ctx, c.ID)
	err = ctx.GetStub().PutState(stateId, updatedStateJSON)
	if err != nil {
		return err
	}

	if isValid {
		ei := CertificateValidEventItem{
			ID:        c.ID,
			SignOrgID: c.SignOrgID,
		}
		event := []CertificateValidEventItem{ei}
		eventJSON, err := json.Marshal(event)
		if err != nil {
			return err
		}
		err = ctx.GetStub().SetEvent("CertificateValid", eventJSON)
	}

	return nil
}

func (s *SmartContract) ReadCertificate(ctx contractapi.TransactionContextInterface, id string) (*Certificate, error) {

	stateId, err := s.NewCertificateStateId(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("id err - %s", err)
	}

	stateJSON, err := ctx.GetStub().GetState(stateId)
	if err != nil {
		return nil, fmt.Errorf("Failed to read from world state: %v", err)
	}
	if stateJSON == nil {
		return nil, fmt.Errorf("Certificate %s does not exist", id)
	}

	var c Certificate = Certificate{
		OrgSignProps: make(map[string][]OrgSignProp),
	}
	err = c.UnmarshalCertificateJSON(stateJSON)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *SmartContract) DeleteOrgCertificate(ctx contractapi.TransactionContextInterface, id string) error {
	org, err := s.ReadMyOrg(ctx)
	if err != nil {
		return err
	}
	stateId, err := s.NewCertificateStateId(ctx, id)
	if err != nil {
		return fmt.Errorf("id err - %s", err)
	}
	stateJSON, err := ctx.GetStub().GetState(stateId)
	if err != nil {
		return fmt.Errorf("Failed to read from world state: %v", err)
	}
	if stateJSON == nil {
		return fmt.Errorf("Certificate %s does not exist", id)
	}
	var c Certificate
	err = c.UnmarshalCertificateJSON(stateJSON)
	if c.OrgId != org.ID {
		return fmt.Errorf("Certificate Org ID is different")
	}
	if err := ctx.GetStub().DelState(stateId); err != nil {
		return fmt.Errorf("Del err - %s", err)
	}
	return nil
}

func (s *SmartContract) CertificateExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {

	stateId, err := s.NewCertificateStateId(ctx, id)
	if err != nil {
		return false, fmt.Errorf("id err - %s", err)
	}

	stateJSON, err := ctx.GetStub().GetState(stateId)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return stateJSON != nil, nil
}

func (t *SmartContract) List(ctx contractapi.TransactionContextInterface, pageSize int32, bookMark string, sortArg string) (*ListCertificate, error) {
	if sortArg != "desc" && sortArg != "asc" {
		return nil, fmt.Errorf("Sort should be \"asc\" or \"desc\"")
	}
	err := t.IsIdentitySuperAdmin(ctx)
	if err != nil {
		return nil, err
	}
	queryString := fmt.Sprintf(`
	{
		"selector": {
			"docType":"%s"
		},
		"sort": [
			{
				"createTxTimestamp": "%s"
			}
		]
	}`, "Certificate", sortArg)
	records, bookMark, err := getQueryResultForQueryStringFromCertificate(ctx, queryString, pageSize, bookMark)
	if err != nil {
		return nil, err
	}
	return &ListCertificate{
		Records:  records,
		BookMark: bookMark,
	}, nil
}

func (s *SmartContract) ListByStatus(ctx contractapi.TransactionContextInterface, pageSize int32, bookMark string, sortArg string, status string) (*ListCertificate, error) {
	if sortArg != "desc" && sortArg != "asc" {
		return nil, fmt.Errorf("Sort should be \"asc\" or \"desc\"")
	}
	if err := s.IsIdentitySuperAdmin(ctx); err != nil {
		return nil, err
	}
	queryString := fmt.Sprintf(`
	{
		"selector": {
			"docType":"%s",
			"status": "%s"
		},
		"sort": [
			{
				"createTxTimestamp": "%s"
			}
		]
	}`, "Certificate", status, sortArg)
	records, bookMark, err := getQueryResultForQueryStringFromCertificate(ctx, queryString, pageSize, bookMark)
	if err != nil {
		return nil, err
	}
	return &ListCertificate{
		Records:  records,
		BookMark: bookMark,
	}, nil
}

func (t *SmartContract) ListOrgCertificate(ctx contractapi.TransactionContextInterface, pageSize int32, bookMark string, sortArg string, orgID string) (*ListCertificate, error) {
	if sortArg != "desc" && sortArg != "asc" {
		return nil, fmt.Errorf("Sort should be \"asc\" or \"desc\"")
	}
	if err := t.IsIdentitySuperAdminOrHasAnyRoleOnOrg(ctx, orgID); err != nil {
		return nil, err
	}
	org, err := t.ReadMyOrg(ctx)
	if err != nil {
		return nil, err
	}
	queryString := fmt.Sprintf(`
	{
		"selector": {
			"docType":"%s",
			"signOrgID": {
				"$elemMatch": {
				   "$eq": "%s"
				}
			}
		},
		"sort": [
			{
				"createTxTimestamp": "%s"
			}
		]
	}`, "Certificate", org.ID, sortArg)
	records, bookMark, err := getQueryResultForQueryStringFromCertificate(ctx, queryString, pageSize, bookMark)
	if err != nil {
		return nil, err
	}
	return &ListCertificate{
		Records:  records,
		BookMark: bookMark,
	}, nil
}

func (t *SmartContract) ListOrgCertificateByStatus(ctx contractapi.TransactionContextInterface, pageSize int32, bookMark string, sortArg string, orgID string, status string) (*ListCertificate, error) {
	if sortArg != "desc" && sortArg != "asc" {
		return nil, fmt.Errorf("Sort should be \"asc\" or \"desc\"")
	}
	if err := t.IsIdentitySuperAdminOrHasAnyRoleOnOrg(ctx, orgID); err != nil {
		return nil, err
	}
	org, err := t.ReadMyOrg(ctx)
	if err != nil {
		return nil, err
	}
	queryString := fmt.Sprintf(`
	{
		"selector": {
			"docType":"%s",
			"status": "%s",
			"signOrgID": {
				"$elemMatch": {
				   "$eq": "%s"
				}
			}
		},
		"sort": [
			{
				"createTxTimestamp": "%s"
			}
		]
	}`, "Certificate", status, org.ID, sortArg)
	records, bookMark, err := getQueryResultForQueryStringFromCertificate(ctx, queryString, pageSize, bookMark)
	if err != nil {
		return nil, err
	}
	return &ListCertificate{
		Records:  records,
		BookMark: bookMark,
	}, nil
}

func getQueryResultForQueryStringFromCertificate(ctx contractapi.TransactionContextInterface, queryString string, pageSize int32, bookMark string) ([]*Certificate, string, error) {
	resultsIterator, meta, err := ctx.GetStub().GetQueryResultWithPagination(queryString, pageSize, bookMark)
	if err != nil {
		return nil, "", err
	}
	defer resultsIterator.Close()

	parsed, err := constructQueryResponseFromIteratorFromCertificate(resultsIterator)
	if err != nil {
		return nil, "", err
	}
	return parsed, meta.Bookmark, nil
}

func constructQueryResponseFromIteratorFromCertificate(resultsIterator shim.StateQueryIteratorInterface) ([]*Certificate, error) {
	var result []*Certificate = make([]*Certificate, 0)
	for resultsIterator.HasNext() {
		queryResult, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		var parsed Certificate
		err = parsed.UnmarshalCertificateJSON(queryResult.Value)
		if err != nil {
			return nil, err
		}
		result = append(result, &parsed)
	}

	return result, nil
}

func verifySignature(hashBytes []byte, pubKeyPem string, signature string) (bool, error) {
	pemBlock, _ := pem.Decode([]byte(pubKeyPem))
	pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		fmt.Println("Parse err")
		return false, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	if err != nil {
		return false, err
	}
	if p, ok := pubKey.(*ecdsa.PublicKey); ok {
		digestValid := ecdsa.VerifyASN1(p, hashBytes, sigBytes)
		return digestValid, nil
	} else {
		return false, fmt.Errorf("Invalid Public key type")
	}
}

func verifyClaimsSignature(claims CertificateClaims, pubKeyPem string, signature string) (bool, error) {
	_, hashBytes, err := NewCertificateClaimsHash(claims)
	if err != nil {
		return false, err
	}
	pemBlock, _ := pem.Decode([]byte(pubKeyPem))
	pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		fmt.Println("Parse err")
		return false, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	if err != nil {
		return false, err
	}
	if p, ok := pubKey.(*ecdsa.PublicKey); ok {
		digestValid := ecdsa.VerifyASN1(p, hashBytes, sigBytes)
		return digestValid, nil
	} else {
		return false, fmt.Errorf("Invalid Public key type")
	}
}

func NewCertificateClaimsHash(d CertificateClaims) (string, []byte, error) {
	hashBytes, err := json.Marshal(&d)
	hasher := crypto.SHA256.New()
	_, err = hasher.Write(hashBytes)
	if err != nil {
		return "", nil, err
	}
	shaBytes := hasher.Sum(nil)
	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha, shaBytes, nil
}

func NewInterfaceHash(d interface{}) (string, []byte, error) {
	hashBytes, err := json.Marshal(&d)
	hasher := crypto.SHA256.New()
	_, err = hasher.Write(hashBytes)
	if err != nil {
		return "", nil, err
	}
	shaBytes := hasher.Sum(nil)
	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha, shaBytes, nil
}

func NewStringHash(d string) (string, []byte, error) {
	hashBytes := []byte(d)
	hasher := crypto.SHA256.New()
	_, err := hasher.Write(hashBytes)
	if err != nil {
		return "", nil, err
	}
	shaBytes := hasher.Sum(nil)
	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha, shaBytes, nil
}

func NestedMapLookup(m map[string]interface{}, ks []string) (rval interface{}, err error) {
	var ok bool

	if len(ks) == 0 { // degenerate input
		return nil, fmt.Errorf("NestedMapLookup needs at least one key")
	}
	if rval, ok = m[ks[0]]; !ok {
		return nil, fmt.Errorf("key not found; remaining keys: %v", ks)
	} else if len(ks) == 1 { // we've reached the final key
		return rval, nil
	} else if m, ok = rval.(map[string]interface{}); !ok {
		return nil, fmt.Errorf("malformed structure at %#v", rval)
	} else { // 1+ more keys
		return NestedMapLookup(m, ks[1:])
	}
}

func (d *Certificate) UnmarshalCertificateJSON(j []byte) error {
	d.OrgSignProps = make(map[string][]OrgSignProp)
	err := json.Unmarshal(j, d)
	return err
}

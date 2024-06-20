package processing

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"go.mozilla.org/pkcs7"
)

var (
	leafCertificateOID  = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.29")
	interCertificateOID = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.2.14")
)

// verifySignature checks the signature of the token, partially using OpenSSL
// due to Go's lack of support for PKCS7.
// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func (t *PKPaymentToken) verifySignature() error {

	// verify the version EC_v1 or RSA_v1
	if !slices.Contains([]string{vEcV1, vRsaV1}, t.PaymentData.Version) {
		return errors.New("invalid version")
	}

	// parse p7
	p7, err := pkcs7.Parse(t.PaymentData.Signature)
	if err != nil {
		return fmt.Errorf("cannot parse the signature: %w", err)
	}

	// load Apple Root CA - G3 root certificate
	root, err := loadRootCertificate(AppleRootCertificatePath)
	if err != nil {
		return fmt.Errorf("error loading the root certificate: %w", err)
	}

	// the certificate list should contain leaf and inter
	if len(p7.Certificates) != 2 {
		return errors.New("the len of certificates is less than 2")
	}

	// Load
	leaf := p7.Certificates[0]
	inter := p7.Certificates[1]

	// Ensure that the certificates contain the correct custom OIDs: 1.2.840.113635.100.6.29 for the leaf certificate and 1.2.840.113635.100.6.2.14 for the intermediate CA. The value for these marker OIDs doesn’t matter, only their presence.
	// Ensure that there’s a valid X.509 chain of trust from the signature to the root CA. Specifically, ensure that the signature was created using the private key that corresponds to the leaf certificate, that the leaf certificate is signed by the intermediate CA, and that the intermediate CA is signed by the Apple Root CA - G3.
	if err := verifyCertificates(root, inter, leaf); err != nil {
		return fmt.Errorf("error when verifying the certificates: %w", err)
	}

	// Validate the token’s signature. For ECC (EC_v1), ensure that the signature is a valid Ellyptical Curve Digital Signature Algorithm (ECDSA) signature (ecdsa-with-SHA256 1.2.840.10045.4.3.2) of the concatenated values of the ephemeralPublicKey, data, transactionId, and applicationData keys. For RSA (RSA_v1), ensure that the signature is a valid RSA signature (RSA-with-SHA256 1.2.840.113549.1.1.11) of the concatenated values of the wrappedKey, data, transactionId, and applicationData keys.
	if err := t.verifyPKCS7Signature(p7); err != nil {
		return fmt.Errorf("error when verifying the pkcs7 signature: %w", err)
	}

	if err := t.verifySigningTime(p7); err != nil {
		return fmt.Errorf("rejected signing time delta (possible replay attack): %w", err)
	}

	return nil
}

// loadRootCertificate loads the root certificate from the disk
func loadRootCertificate(path string) (*x509.Certificate, error) {
	rootPEMBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading the root certificate: %w", err)
	}
	rootPEM, rest := pem.Decode(rootPEMBytes)
	if rootPEM == nil {
		return nil, errors.New("error decoding the root certificate")
	}
	if rest != nil && len(rest) > 0 {
		return nil, errors.New("trailing data after the root certificate")
	}

	root, err := x509.ParseCertificate(rootPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing the root certificate: %w", err)
	}
	if !root.IsCA {
		return nil, errors.New("the certificate seems not to be a CA")
	}

	return root, nil
}

// verifyCertificates checks the validity of the certificate chain used for
// signing the token, and verifies the chain of trust from root to leaf
func verifyCertificates(root, inter, leaf *x509.Certificate) error {
	// Ensure the certificates contain the correct OIDs
	if _, err := extractExtension(inter, interCertificateOID); err != nil {
		return fmt.Errorf("invalid intermediate cert Apple extension: %w", err)
	}
	if _, err := extractExtension(leaf, leafCertificateOID); err != nil {
		return fmt.Errorf("invalid leaf cert Apple extension: %w", err)
	}

	// Verify the chain of trust
	if err := inter.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("intermediate cert is not trusted by root: %w", err)
	}
	if err := leaf.CheckSignatureFrom(inter); err != nil {
		return fmt.Errorf("leaf cert is not trusted by intermediate cert: %w", err)
	}

	return nil
}

func (t *PKPaymentToken) verifyPKCS7Signature(p7 *pkcs7.PKCS7) error {
	// we assigned the signed data to the p7 content because it could be detached in the previous steps
	p7.Content = t.signedData()
	return p7.Verify()
}

// signedData returns the data signed by the client's Secure Element as defined
// in Apple's documentation: https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func (t *PKPaymentToken) signedData() []byte {
	signed := bytes.NewBuffer(nil)

	switch t.PaymentData.Version {
	case vEcV1:
		signed.Write(t.PaymentData.Header.EphemeralPublicKey)
	case vRsaV1:
		signed.Write(t.PaymentData.Header.WrappedKey)
	}

	signed.Write(t.PaymentData.Data)
	trIDHex, _ := hex.DecodeString(t.PaymentData.Header.TransactionID)
	signed.Write(trIDHex)
	appDataHex, _ := hex.DecodeString(t.PaymentData.Header.ApplicationData)
	signed.Write(appDataHex)
	return signed.Bytes()
}

// verifySigningTime checks that the time of signing of the token is before the
// transaction was received, and that the gap between the two is not too
// significant. It uses the variable TransactionTimeWindow as a limit.
func (t *PKPaymentToken) verifySigningTime(p7 *pkcs7.PKCS7) error {
	transactionTime := time.Now()
	if !t.transactionTime.IsZero() {
		transactionTime = t.transactionTime
	}

	signedTime := time.Time{}
	if err := p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeSigningTime, &signedTime); err != nil {
		return err
	}

	// Check that both times are separated by less than TransactionTimeWindow
	delta := transactionTime.Sub(signedTime)
	if delta < -time.Second {
		return fmt.Errorf(
			"the transaction occured before the signing (%s difference)",
			delta.String(),
		)
	}
	if delta > TransactionTimeWindow {
		return fmt.Errorf(
			"the transaction occured after the allowed time window (%s)",
			delta.String(),
		)
	}
	return nil
}

package processing

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"errors"
)

// extractMerchantHash extracts the merchant hash stored in a certificate. It is
// stored by Apple during the signature of the certificate.
// It is the merchant ID hashed with SHA-256 and represented in hexadecimal
func extractMerchantHash(cert tls.Certificate) ([]byte, error) {
	if cert.Certificate == nil {
		return nil, errors.New("nil certificate")
	}

	// Parse the leaf certificate of the certificate chain
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("certificate parsing error: %w", err)
	}

	extValue, err := extractExtension(leaf, merchantIDHashOID)
	if err != nil {
		return nil, fmt.Errorf("error finding the hash extension: %w", err)
	}
	// First two bytes are "@."
	if len(extValue) != 66 {
		return nil, errors.New("invalid hash length")
	}
	merchantIDString, err := hex.DecodeString(string(extValue[2:]))
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}
	return merchantIDString, nil
}

// extractExtension returns the value of a certificate extension if it exists
func extractExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("nil certificate")
	}

	var res []byte
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		res = ext.Value
	}
	if res == nil {
		return nil, errors.New("extension not found")
	}

	return res, nil
}

// mustParseASN1ObjectIdentifier calls parseASN1ObjectIdentifier and panics if
// it returns an error
func mustParseASN1ObjectIdentifier(id string) asn1.ObjectIdentifier {
	oid, err := parseASN1ObjectIdentifier(id)
	if err != nil {
		panic(fmt.Errorf("error parsing the OID: %w", err))
	}
	return oid
}

// parseASN1ObjectIdentifier parses an ASN.1 object identifier string of the
// form x.x.x.x.x.x.x.x into a Go asn1.ObjectIdentifier
func parseASN1ObjectIdentifier(id string) (asn1.ObjectIdentifier, error) {
	idSplit := strings.Split(id, ".")
	oid := make([]int, len(idSplit))
	for i, str := range idSplit {
		r, err := strconv.Atoi(str)
		if err != nil {
			return nil, fmt.Errorf("error parsing %s: %w", str, err)
		}
		oid[i] = r
	}
	return oid, nil
}

func checkValidity(cert tls.Certificate) error {
	if cert.Certificate == nil {
		return errors.New("nil certificate")
	}

	// Parse the leaf certificate of the certificate chain
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("certificate parsing error: %w", err)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{}); err != nil {
		if errors.As(err, &x509.UnknownAuthorityError{}) {
			// TODO: certs signed by apple are somehow recognized as self-signed,
			// probably we need to figure out how to properly configure CA chain in docker
			// for now just validate expiration period
			log.Printf("cert recognized as self signed: %e", err)

			now := time.Now()
			if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
				return errors.New("certificate is expired or not yet valid")
			}
			return nil
		}

		return err
	}

	return nil
}

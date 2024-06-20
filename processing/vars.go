package processing

import "time"

var (
	// merchantIDHashOID is the ASN.1 object identifier of Apple's extension
	// for merchant ID hash in merchant/processing certificates
	merchantIDHashOID = mustParseASN1ObjectIdentifier(
		"1.2.840.113635.100.6.32",
	)

	// TransactionTimeWindow is the window of time, in minutes, where
	// transactions can fit to limit replay attacks
	TransactionTimeWindow = 5 * time.Minute
)

const (
	vEcV1  = "EC_v1"
	vRsaV1 = "RSA_v1"
)

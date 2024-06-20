package processing

import (
	"crypto/tls"
	"fmt"
)

func New(merchantId string, processingKeyPem, processingCertPem []byte) (*Processing, error) {
	cert, err := tls.X509KeyPair(processingKeyPem, processingCertPem)
	if err != nil {
		return nil, fmt.Errorf("error loading the certificate: %w", err)
	}
	return &Processing{
		identifier:            merchantId,
		processingCertificate: &cert,
	}, nil
}

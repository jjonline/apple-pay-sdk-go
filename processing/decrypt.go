package processing

import (
	"crypto/tls"
	"fmt"
)

// New construct Apple Pay processing struct instance
//
//   - processingKeyPem   your Apple Pay processing private key pem format byte stream
//   - processingCertPem  your Apple Pay processing certificate pem format byte stream
//   - rootCaPem		  Apple Pay Root CA pem byte stream
//
// about pem format rootCaPem DER format file at: https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
// use openssl transfer to pem format as: openssl x509 -inform der -in AppleRootCA-G3.cer -out AppleRootCA-G3-converted.pem
func New(merchantId string, processingKeyPem, processingCertPem []byte, rootCaPem []byte) (*Processing, error) {
	cert, err := tls.X509KeyPair(processingCertPem, processingKeyPem)
	if err != nil {
		return nil, fmt.Errorf("error loading the certificate: %w", err)
	}
	return &Processing{
		identifier:            merchantId,
		processingCertificate: &cert,
		rootCaCertificatePem:  rootCaPem,
	}, nil
}

func LoadProcessingKeyPair(processingKeyPem, processingCertPem []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(processingCertPem, processingKeyPem)
}

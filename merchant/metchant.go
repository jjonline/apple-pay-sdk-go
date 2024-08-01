package merchant

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/jjonline/go-lib-backend/guzzle"
	"net/http"
	"time"
)

const (
	sessionGlobalApi  = "https://apple-pay-gateway.apple.com/paymentservices/paymentSession"
	sessionChinaCnApi = "https://cn-apple-pay-gateway.apple.com/paymentservices/paymentSession"
)

// New create a new merchant request struct instance
//
//   - merchantId      merchant id, for example `merchant.com.google.web.pay`
//   - merchantKeyPem  Merchant Identity Certificate's private key, PEM encoding format
//   - merchantCertPem Merchant Identity Certificate, PEM encoding format
//   - rootCaPem	   CA root certificate that issued your Merchant Identity Certificate, PEM encoding format
//
// about RootCA ref link:
//  1. https://developer.apple.com/support/expiration/
//  2. https://www.apple.com/certificateauthority/
//  3. https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
//
// The CA specified here solves the problem that some
// op system do not have a built-in root certificate,
// causing the certificate to be untrustworthy.
//
// You should use openssl to check which CA issued your
// certificate and then determine which one of G1 to G8 to download. In 2024, it will be G3.
//
//	openssl x509 -in certificate.pem -text -noout
func New(merchantId string, merchantKeyPem, merchantCertPem, rootCaPem []byte) (*Merchant, error) {
	if merchantId == "" || merchantKeyPem == nil || merchantCertPem == nil || rootCaPem == nil {
		return nil, fmt.Errorf("invalid param")
	}

	// init http client certificate
	cert, err := tls.X509KeyPair(merchantCertPem, merchantKeyPem)
	if err != nil {
		return nil, fmt.Errorf("init http client certificate error: %w", err)
	}

	ca := x509.NewCertPool()
	ca.AppendCertsFromPEM(rootCaPem)
	gClient := guzzle.New(&http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 10 * time.Second,
			DisableCompression:  true,
			MaxIdleConns:        400,
			MaxIdleConnsPerHost: 50,
			MaxConnsPerHost:     100,
			IdleConnTimeout:     120 * time.Second,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.RequestClientCert,
				ClientCAs:    ca,
			},
		},
	}, nil)

	return &Merchant{
		merchantId:          merchantId,
		merchantCertificate: &cert,
		guzzleClient:        gClient,
		host:                sessionGlobalApi,
		atChineseMainland:   false,
	}, nil
}

// Merchant ApplePay merchant struct
type Merchant struct {
	merchantId          string
	merchantCertificate *tls.Certificate
	guzzleClient        *guzzle.Client
	host                string
	atChineseMainland   bool
}

// SwitchToChineseMainland  Switch to Apple Pay in Mainland China
func (m *Merchant) SwitchToChineseMainland() *Merchant {
	m.atChineseMainland = true
	m.host = sessionChinaCnApi
	return m
}

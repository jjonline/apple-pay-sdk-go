package merchant

import (
	"context"
	"encoding/json"
)

// ApplePayPaymentSession struct fo ApplePay payment session
// https://developer.apple.com/documentation/apple_pay_on_the_web/apple_pay_js_api/requesting_an_apple_pay_payment_session
type ApplePayPaymentSession struct {
	EpochTimestamp                 int64  `json:"epochTimestamp"`
	ExpiresAt                      int64  `json:"expiresAt"`
	MerchantSessionIdentifier      string `json:"merchantSessionIdentifier"`
	Nonce                          string `json:"nonce"`
	MerchantIdentifier             string `json:"merchantIdentifier"`
	DomainName                     string `json:"domainName"`
	DisplayName                    string `json:"displayName"`
	Signature                      string `json:"signature"`
	OperationalAnalyticsIdentifier string `json:"operationalAnalyticsIdentifier"`
	Retries                        int    `json:"retries"`
	PspID                          string `json:"pspId"`
}

// GetApplePayPaymentSession Get ApplePayPaymentSession from Apple Pay server use http client tls verify
//
//   - displayName
//   - initiative web|messaging
//   - initiativeContext
//
// param spec ref: https://developer.apple.com/documentation/apple_pay_on_the_web/apple_pay_js_api/requesting_an_apple_pay_payment_session#3199965
//
// function ref: https://developer.apple.com/documentation/apple_pay_on_the_web/apple_pay_js_api/requesting_an_apple_pay_payment_session
func (m *Merchant) GetApplePayPaymentSession(displayName string, initiative, initiativeContext string) (*ApplePayPaymentSession, error) {
	param := map[string]string{
		"merchantIdentifier": m.merchantId,
		"displayName":        displayName,
		"initiative":         initiative,
		"initiativeContext":  initiativeContext,
	}
	res, err := m.guzzleClient.PostJSON(context.TODO(), m.host, param, nil)
	if err != nil {
		return nil, err
	}

	var result = &ApplePayPaymentSession{}
	err = json.Unmarshal(res.Body, result)

	return result, err
}

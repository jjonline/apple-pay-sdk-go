package processing

import (
	"crypto/tls"
	"time"
)

// ApplePayPayment is the full response from the user's device after an Apple Pay request
// https://developer.apple.com/documentation/apple_pay_on_the_web/applepaypayment
type ApplePayPayment struct {
	ShippingContact *ApplePayPaymentContact `json:"shippingContact,omitempty"`
	BillingContact  *ApplePayPaymentContact `json:"billingContact,omitempty"`
	Token           ApplePayPaymentToken    `json:"token"`
}

// ApplePayPaymentContact is the struct that contains billing/shipping information from an Apple Pay response
// https://developer.apple.com/documentation/apple_pay_on_the_web/applepaypaymentcontact
type ApplePayPaymentContact struct {
	PhoneNumber           string   `json:"phoneNumber"`
	EmailAddress          string   `json:"emailAddress"`
	GivenName             string   `json:"givenName"`
	FamilyName            string   `json:"familyName"`
	PhoneticGivenName     string   `json:"phoneticGivenName"`
	PhoneticFamilyName    string   `json:"phoneticFamilyName"`
	AddressLines          []string `json:"addressLines"`
	Locality              string   `json:"locality"`
	SubLocality           string   `json:"subLocality"`
	PostalCode            string   `json:"postalCode"`
	AdministrativeArea    string   `json:"administrativeArea"`
	SubAdministrativeArea string   `json:"subAdministrativeArea"`
	Country               string   `json:"country"`
	CountryCode           string   `json:"countryCode"`
}

// ApplePayPaymentToken
// https://developer.apple.com/documentation/apple_pay_on_the_web/applepaypaymenttoken
type ApplePayPaymentToken struct {
	transactionTime       time.Time
	TransactionIdentifier string                `json:"transactionIdentifier"`
	PaymentMethod         ApplePayPaymentMethod `json:"paymentMethod"`
	PaymentData           PaymentData           `json:"paymentData"`
}

// ApplePayPaymentMethod
// https://developer.apple.com/documentation/apple_pay_on_the_web/applepaypaymentmethod
type ApplePayPaymentMethod struct {
	Type           string                 `json:"type"`
	Network        string                 `json:"network"`
	DisplayName    string                 `json:"displayName"`
	BillingContact ApplePayPaymentContact `json:"billingContact,omitempty"`
	// ApplePayPaymentPass
}

// PaymentData
// https://developer.apple.com/documentation/apple_pay_on_the_web/applepaypaymenttoken/1916115-paymentdata
type PaymentData struct {
	Version   string
	Signature []byte
	Header    Header
	Data      []byte
}

// Header header for PaymentData
type Header struct {
	ApplicationData    string
	EphemeralPublicKey []byte
	WrappedKey         []byte
	PublicKeyHash      []byte
	TransactionID      string
}

// Token is the decrypted form of ApplePayPayment.Token.PaymentData.Data
type Token struct {
	// ApplicationPrimaryAccountNumber is the device-specific account number of the card that funds this
	// transaction
	ApplicationPrimaryAccountNumber string
	// ApplicationExpirationDate is the card expiration date in the format YYMMDD
	ApplicationExpirationDate string
	// CurrencyCode is the ISO 4217 numeric currency code, as a string to preserve leading zeros
	CurrencyCode string
	// TransactionAmount is the value of the transaction
	TransactionAmount float64
	// CardholderName is the name on the card
	CardholderName string
	// DeviceManufacturerIdentifier is a hex-encoded device manufacturer identifier
	DeviceManufacturerIdentifier string
	// PaymentDataType is either 3DSecure or, if using Apple Pay in China, EMV
	PaymentDataType string
	// PaymentData contains detailed payment data
	PaymentData struct {
		// 3-D Secure fields

		// OnlinePaymentCryptogram is the 3-D Secure cryptogram
		OnlinePaymentCryptogram []byte
		// ECIIndicator is the Electronic Commerce Indicator for the status of 3-D Secure
		ECIIndicator string

		// EMV fields

		// EMVData is the output from the Secure Element
		EMVData []byte
		// EncryptedPINData is the PIN encrypted with the bank's key
		EncryptedPINData string
	}
}

// Processing usage struct
type Processing struct {
	identifier            string
	processingCertificate *tls.Certificate
}

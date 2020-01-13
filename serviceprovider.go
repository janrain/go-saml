package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// ServiceProvider provides settings to configure a SAML Service Provider.
// Expect only one IDP per SP in this configuration.
// If you need to configure multipe IDPs for an SP then configure
// multiple instances of this module.
type ServiceProvider struct {
	AssertionConsumerServiceURL string
	IDPSSOURL                   string
	IssuerURL                   string
	PrivateKey                  *rsa.PrivateKey
	PublicCert                  *x509.Certificate
	IDPPublicCert               *x509.Certificate
	SignRequest                 bool
	CompressRequest             bool
}

// AuthnRequest creates an AuthnRequest object
func (sp *ServiceProvider) AuthnRequest() *AuthnRequest {
	return NewAuthnRequest(sp.IssuerURL, sp.AssertionConsumerServiceURL, sp.IDPSSOURL)
}

// EncodeAuthnRequest returns an encoded AuthnRequest
func (sp *ServiceProvider) EncodeAuthnRequest(ar *AuthnRequest) (string, error) {
	if sp.SignRequest {
		err := ar.Sign(sp.PrivateKey, sp.PublicCert)
		if err != nil {
			return "", err
		}
	}
	if sp.CompressRequest {
		return ar.CompressedEncodedString()
	}
	return ar.EncodedString()
}

// AuthnRequestURL generates a URL for the encoded AuthnRequest
// with the SAMLRequest and RelayState query params set
func (sp *ServiceProvider) AuthnRequestURL(encodedXML, state string) (*url.URL, error) {
	u, err := url.Parse(sp.IDPSSOURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IDPSSOURL: %w", err)
	}

	q := u.Query()
	q.Add("SAMLRequest", encodedXML)
	q.Add("RelayState", state)
	u.RawQuery = q.Encode()
	return u, nil
}

// ValidateResponse validates a Response
func (sp *ServiceProvider) ValidateResponse(resp *Response) error {
	if resp.Version != "2.0" {
		return fmt.Errorf("unsupported SAML Version: %s", resp.Version)
	}

	if len(resp.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if len(resp.Assertion.ID) == 0 {
		return errors.New("missing ID attribute on SAML Assertion")
	}

	if resp.Destination != sp.AssertionConsumerServiceURL {
		return fmt.Errorf("destination mismatch, expected: %s not %s", sp.AssertionConsumerServiceURL, resp.Destination)
	}

	if resp.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != sp.AssertionConsumerServiceURL {
		return fmt.Errorf("subject recipient mismatch, expected: %s not %s", sp.AssertionConsumerServiceURL, resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}

	expires, err := time.Parse(time.RFC3339, resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter)
	if err != nil {
		return fmt.Errorf("failed to parse NotOnOrAfter (%s): %w", resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter, err)
	}
	if expires.Before(time.Now()) {
		return fmt.Errorf("assertion expired on: %s", resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter)
	}

	return resp.ValidateSignature([]*x509.Certificate{sp.IDPPublicCert})
}

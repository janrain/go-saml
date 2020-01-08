package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
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

// EntityDescriptor creates an EntityDescriptor object
func (sp *ServiceProvider) EntityDescriptor() *EntityDescriptor {
	cert := sp.EncodedPublicCert()
	return &EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityID: sp.AssertionConsumerServiceURL,
		Extensions: Extensions{
			XMLName: xml.Name{
				Local: "md:Extensions",
			},
			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",
		},
		SPSSODescriptor: SPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			SigningKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "signing",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: cert,
						},
					},
				},
			},
			EncryptionKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use: "encryption",
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
							Cert: cert,
						},
					},
				},
			},
			AssertionConsumerServices: []AssertionConsumerService{
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: sp.AssertionConsumerServiceURL,
					Index:    "0",
				},
			},
		},
	}
}

// EncodedPublicCert returns the public cert as base64 encoded string
func (sp *ServiceProvider) EncodedPublicCert() string {
	return base64.StdEncoding.EncodeToString(sp.PublicCert.Raw)
}

// EntityDescriptorXML generates the SP metadata XML doc
func (sp *ServiceProvider) EntityDescriptorXML() (string, error) {
	ed := sp.EntityDescriptor()
	b, err := xml.MarshalIndent(ed, "", "\t")
	if err != nil {
		return "", fmt.Errorf("failed to marshal xml: %w", err)
	}

	return fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b), nil
}

// AuthnRequest creates an AuthnRequest object
func (sp *ServiceProvider) AuthnRequest() *AuthnRequest {
	return NewAuthnRequest(sp.IssuerURL, sp.AssertionConsumerServiceURL, sp.IDPSSOURL)
}

// EncodeAuthnRequest returns an encoded AuthnRequest
func (sp *ServiceProvider) EncodeAuthnRequest(ar *AuthnRequest) (string, error) {
	if sp.SignRequest {
		if sp.CompressRequest {
			return ar.CompressedEncodedSignedString("/AuthnRequest", sp.PrivateKey, sp.PublicCert)
		}
		return ar.EncodedSignedString("/AuthnRequest", sp.PrivateKey, sp.PublicCert)
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

	// check for signature in root then in assertion
	var path string
	if len(resp.Signature.SignatureValue.Value) > 0 {
		path = "/Response"
	} else if len(resp.Assertion.Signature.SignatureValue.Value) > 0 {
		path = "/Response/Assertion"
	} else {
		return errors.New("no signature found")
	}

	return resp.VerifySignature(path, []*x509.Certificate{sp.IDPPublicCert})
}

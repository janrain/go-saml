package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"time"

	"github.com/janrain/go-saml/util"
	"github.com/janrain/go-saml/xmlsec"
)

const RequestXMLID = "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest"

// AuthnRequest creates an AuthnRequest object
func (sp *ServiceProvider) AuthnRequest() *AuthnRequest {
	ar := NewAuthnRequest()
	ar.AssertionConsumerServiceURL = sp.AssertionConsumerServiceURL
	ar.Destination = sp.IDPSSOURL
	ar.Issuer.Url = sp.IDPSSODescriptorURL
	ar.Signature.KeyInfo.X509Data.X509Certificate.Cert = sp.PublicCert()

	if !sp.SignRequest {
		ar.SAMLSIG = ""
		ar.Signature = nil
	}

	return ar
}

// EncodedAuthnRequest returns an encoded AuthnRequest
func (sp *ServiceProvider) EncodeAuthnRequest(ar *AuthnRequest) (string, error) {
	if sp.SignRequest {
		if sp.UseCompression {
			return ar.CompressedEncodedSignedString(sp.PrivateKeyPath)
		} else {
			return ar.EncodedSignedString(sp.PrivateKeyPath)
		}
	} else {
		if sp.UseCompression {
			return ar.CompressedEncodedString()
		} else {
			return ar.EncodedString()
		}
	}
}

// AuthnRequestURL generates a URL for the encoded AuthnRequest
// with the SAMLRequest and RelayState query params set
func (sp *ServiceProvider) AuthnRequestURL(encodedXML, state string) (*url.URL, error) {
	u, err := url.Parse(sp.IDPSSOURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Add("SAMLRequest", encodedXML)
	q.Add("RelayState", state)
	u.RawQuery = q.Encode()
	return u, nil
}

// NewAuthnRequest constructs an AuthnRequest
func NewAuthnRequest() *AuthnRequest {
	id := util.ID()
	return &AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:                     "http://www.w3.org/2000/09/xmldsig#",
		ID:                          id,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url:  "", // caller must populate ar.AppSettings.Issuer
			SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
		Signature: &Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: Transform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
	}
}

func (ar *AuthnRequest) String() (string, error) {
	b, err := xml.MarshalIndent(ar, "", "\t")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (ar *AuthnRequest) SignedString(privateKeyPath string) (string, error) {
	s, err := ar.String()
	if err != nil {
		return "", err
	}

	return xmlsec.Sign(s, privateKeyPath, RequestXMLID)
}

func (ar *AuthnRequest) EncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := ar.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

func (ar *AuthnRequest) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	signed, err := ar.SignedString(privateKeyPath)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

func (ar *AuthnRequest) EncodedString() (string, error) {
	saml, err := ar.String()
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(saml))
	return b64XML, nil
}

func (ar *AuthnRequest) CompressedEncodedString() (string, error) {
	saml, err := ar.String()
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(saml))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

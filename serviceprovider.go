package saml

import (
	"encoding/xml"
	"fmt"

	"github.com/janrain/go-saml/util"
)

// ServiceProvider provides settings to configure a SAML Service Provider.
// Expect only one IDP per SP in this configuration.
// If you need to configure multipe IDPs for an SP then configure
// multiple instances of this module.
type ServiceProvider struct {
	PublicCertPath              string
	PrivateKeyPath              string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCertPath           string
	IDPTrustedCertPaths         []string
	AssertionConsumerServiceURL string
	SignRequest                 bool
	CompressRequest             bool

	hasInit       bool
	publicCert    string
	privateKey    string
	iDPPublicCert string
}

// Init loads any keys and certificates
func (sp *ServiceProvider) Init() (err error) {
	if sp.hasInit {
		return nil
	}
	sp.hasInit = true

	if sp.SignRequest {
		sp.publicCert, err = util.LoadCertificate(sp.PublicCertPath)
		if err != nil {
			return err
		}
		sp.privateKey, err = util.LoadCertificate(sp.PrivateKeyPath)
		if err != nil {
			return err
		}
	}

	sp.iDPPublicCert, err = util.LoadCertificate(sp.IDPPublicCertPath)
	if err != nil {
		return err
	}

	return nil
}

// PublicCert returns the SP public cert contents
func (sp *ServiceProvider) PublicCert() string {
	if !sp.hasInit {
		panic("Must call Init() first")
	}
	return sp.publicCert
}

// PrivateKey returns the SP private key contents
func (sp *ServiceProvider) PrivateKey() string {
	if !sp.hasInit {
		panic("Must call Init() first")
	}
	return sp.privateKey
}

// IDPPublicCert returns the IDP public cert contents
func (sp *ServiceProvider) IDPPublicCert() string {
	if !sp.hasInit {
		panic("Must call Init() first")
	}
	return sp.iDPPublicCert
}

// EntityDescriptor creates an EntityDescriptor object
func (sp *ServiceProvider) EntityDescriptor() *EntityDescriptor {
	return &EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityId: sp.AssertionConsumerServiceURL,
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
							Cert: sp.PublicCert(),
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
							Cert: sp.PublicCert(),
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

// EntityDescriptorXML generates the SP metadata XML doc
func (sp *ServiceProvider) EntityDescriptorXML() (string, error) {
	ed := sp.EntityDescriptor()
	b, err := xml.MarshalIndent(ed, "", "\t")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b), nil
}

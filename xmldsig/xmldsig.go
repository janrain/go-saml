package xmldsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
)

const (
	idAttribute = "ID" // xml id attribute name
	nsPrefix    = "ds" // signature namespace prefix
)

// keyStore implements dsig.X509KeyStore
type keyStore struct {
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
}

// GetKeyPair implements dsig.X509KeyStore
func (ks keyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.publicCert.Raw, nil
}

// Sign creates a signature for the given xml element and returns the signature
func Sign(element *etree.Element, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (*etree.Element, error) {
	signingCtx := &dsig.SigningContext{
		Hash: crypto.SHA1,
		KeyStore: keyStore{
			privateKey: privateKey,
			publicCert: publicCert,
		},
		IdAttribute:   idAttribute,
		Prefix:        nsPrefix,
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}
	signedElement, err := signingCtx.SignEnveloped(element)
	if err != nil {
		return nil, err
	}

	return signedElement.Child[len(signedElement.Child)-1].(*etree.Element), nil
}

// VerifySignature checks the signature in the xml element
func VerifySignature(element *etree.Element, certs []*x509.Certificate) error {
	validationCtx := &dsig.ValidationContext{
		CertificateStore: &dsig.MemoryX509CertificateStore{Roots: certs},
		IdAttribute:      idAttribute,
	}

	if _, err := validationCtx.Validate(element); err != nil {
		return err
	}

	return nil
}

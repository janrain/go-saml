package xmldsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

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

// Sign adds a signature to the xml document element at specified XPath
func Sign(rawXML, xPath string, privateKey *rsa.PrivateKey, publicCert *x509.Certificate) (string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(rawXML); err != nil {
		return "", fmt.Errorf("failed to parse xml: %w", err)
	}

	root := doc.Root()
	element := root.FindElement(xPath)
	if element == nil {
		return "", fmt.Errorf("xml element not found at path: %s", xPath)
	}
	// remove existing signatures
	for _, e := range element.ChildElements() {
		if e.Tag == "Signature" {
			element.RemoveChild(e)
		}
	}

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
		return "", fmt.Errorf("failed to sign xml element at path %s: %w", xPath, err)
	}

	// remove unsigned element and add signed version
	parent := element.Parent()
	var idx int
	for i, e := range parent.ChildElements() {
		if e == element {
			idx = i
			parent.RemoveChild(e)
		}
	}
	parent.InsertChildAt(idx, signedElement)

	out, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to generate signed xml: %w", err)
	}
	return out, nil
}

// VerifySignature checks the signature in the xml document at the specified XPath
func VerifySignature(rawXML, xPath string, certs []*x509.Certificate) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(rawXML); err != nil {
		return fmt.Errorf("failed to parse xml: %w", err)
	}

	element := doc.Root().FindElement(xPath)
	if element == nil {
		return fmt.Errorf("xml element not found at path %s", xPath)
	}

	validationCtx := &dsig.ValidationContext{
		CertificateStore: &dsig.MemoryX509CertificateStore{Roots: certs},
		IdAttribute:      idAttribute,
	}

	if _, err := validationCtx.Validate(element); err != nil {
		return fmt.Errorf("failed to validate xml signature at path %s: %w", xPath, err)
	}

	return nil
}

package saml_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/janrain/go-saml"
	"github.com/janrain/go-saml/util"

	"github.com/stretchr/testify/suite"
)

const (
	arACS         = "http://localhost/acs"
	arIssuer      = "http://localhost"
	arDestination = "http://idp.test"
	arXPath       = "/AuthnRequest"
)

type AuthnRequestSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
	ar         *saml.AuthnRequest
}

func (s *AuthnRequestSuite) SetupSuite() {
	s.privateKey, s.publicCert = util.TestKeyPair()
	s.ar = saml.NewAuthnRequest(arIssuer, arACS, arDestination)
}

func (s *AuthnRequestSuite) ValidateAuthnRequest(ar *saml.AuthnRequest, signed bool) {
	s.Equal(arACS, ar.AssertionConsumerServiceURL)
	s.Equal(arIssuer, ar.Issuer.Value)
	s.Equal(arDestination, ar.Destination)

	if signed {
		err := ar.VerifySignature(arXPath, []*x509.Certificate{s.publicCert})
		s.NoError(err)
	}
}

func (s *AuthnRequestSuite) TestSignedString() {
	x, err := s.ar.SignedString(arXPath, s.privateKey, s.publicCert)
	s.NoError(err)

	parsedAr, err := saml.ParseAuthnRequest(x)
	s.NoError(err)

	s.ValidateAuthnRequest(parsedAr, true)
}

func (s *AuthnRequestSuite) TestEncodedString() {
	x, err := s.ar.EncodedString()
	s.NoError(err)

	parsedAr, err := saml.ParseEncodedAuthnRequest(x)
	s.NoError(err)

	s.ValidateAuthnRequest(parsedAr, false)
}

func (s *AuthnRequestSuite) TestCompressedEncodedString() {
	x, err := s.ar.CompressedEncodedString()
	s.NoError(err)

	parsedAr, err := saml.ParseEncodedAuthnRequest(x)
	s.NoError(err)

	s.ValidateAuthnRequest(parsedAr, false)
}

func (s *AuthnRequestSuite) TestCompressedEncodedSignedString() {
	x, err := s.ar.CompressedEncodedSignedString(arXPath, s.privateKey, s.publicCert)
	s.NoError(err)

	parsedAr, err := saml.ParseEncodedAuthnRequest(x)
	s.NoError(err)

	s.ValidateAuthnRequest(parsedAr, true)
}

func TestAuthnRequestSuite(t *testing.T) {
	suite.Run(t, &AuthnRequestSuite{})
}

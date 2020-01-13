package saml_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/janrain/go-saml"
	"github.com/janrain/go-saml/testutil"

	"github.com/stretchr/testify/suite"
)

const (
	arACS         = "http://localhost/acs"
	arIssuer      = "http://localhost"
	arDestination = "http://idp.test"
)

type AuthnRequestSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
	ar         *saml.AuthnRequest
	signed     bool
}

func (s *AuthnRequestSuite) SetupSuite() {
	s.privateKey, s.publicCert = testutil.TestKeyPair()
}

func (s *AuthnRequestSuite) SetupTest() {
	s.ar = saml.NewAuthnRequest(arIssuer, arACS, arDestination)
}

func (s *AuthnRequestSuite) ValidateAuthnRequest() {
	s.Equal(arACS, s.ar.AssertionConsumerServiceURL)
	s.Equal(arIssuer, s.ar.Issuer.Value)
	s.Equal(arDestination, s.ar.Destination)

	if s.signed {
		err := s.ar.ValidateSignature([]*x509.Certificate{s.publicCert})
		s.NoError(err)
	}
}

func (s *AuthnRequestSuite) TestSigned() {
	err := s.ar.Sign(s.privateKey, s.publicCert)
	s.NoError(err)
	s.NotNil(s.ar.Signature)
	s.signed = true

	s.ValidateAuthnRequest()

	out, err := s.ar.String()
	s.NoError(err)

	s.ar, err = saml.ParseAuthnRequest(out)
	s.NoError(err)

	s.ValidateAuthnRequest()
}

func (s *AuthnRequestSuite) TestEncoded() {
	out, err := s.ar.EncodedString()
	s.NoError(err)

	s.ar, err = saml.ParseEncodedAuthnRequest(out)
	s.NoError(err)

	s.ValidateAuthnRequest()
}

func (s *AuthnRequestSuite) TestCompressedEncoded() {
	out, err := s.ar.CompressedEncodedString()
	s.NoError(err)

	s.ar, err = saml.ParseEncodedAuthnRequest(out)
	s.NoError(err)

	s.ValidateAuthnRequest()
}

func TestAuthnRequestSuite(t *testing.T) {
	suite.Run(t, &AuthnRequestSuite{})
}

package saml_test

import (
	"testing"

	"github.com/janrain/go-saml"

	"github.com/stretchr/testify/suite"
)

type AuthnRequestTestSuite struct {
	suite.Suite
	sp *saml.ServiceProvider
	ar *saml.AuthnRequest
}

func (s *AuthnRequestTestSuite) SetupTest() {
	s.sp = &saml.ServiceProvider{
		PublicCertPath:              "./xmlsec/testdata/default.crt",
		PrivateKeyPath:              "./xmlsec/testdata/default.key",
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./xmlsec/testdata/default.crt",
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SignRequest:                 true,
		UseCompression:              true,
	}
	err := s.sp.Init()
	if err != nil {
		panic(err)
	}
	s.ar = s.sp.AuthnRequest()
}

func (s *AuthnRequestTestSuite) TestSignedAuthnRequest() {
	encoded, err := s.sp.EncodeAuthnRequest(s.ar)
	s.NoError(err)
	s.NotEmpty(encoded)

	u, err := s.sp.AuthnRequestURL(encoded, "asdf")
	s.NoError(err)
	s.Equal("http", u.Scheme)
	s.Equal("www.onelogin.net", u.Host)
	q := u.Query()
	s.Equal(encoded, q.Get("SAMLRequest"))
	s.Equal("asdf", q.Get("RelayState"))
}

func TestAuthnRequest(t *testing.T) {
	suite.Run(t, &AuthnRequestTestSuite{})
}

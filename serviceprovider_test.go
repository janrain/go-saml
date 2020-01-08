package saml_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/janrain/go-saml"
	"github.com/janrain/go-saml/util"

	"github.com/stretchr/testify/suite"
)

type ServiceProviderSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	publicCert *x509.Certificate
	sp         *saml.ServiceProvider
}

func (s *ServiceProviderSuite) SetupSuite() {
	s.privateKey, s.publicCert = util.TestKeyPair()
	s.sp = &saml.ServiceProvider{
		AssertionConsumerServiceURL: "http://localhost:8080/callback",
		IssuerURL:                   "http://localhost:8080",
		IDPSSOURL:                   "http://www.onelogin.net",
		PrivateKey:                  s.privateKey,
		PublicCert:                  s.publicCert,
		IDPPublicCert:               s.publicCert,
		SignRequest:                 true,
		CompressRequest:             true,
	}
}

func (s *ServiceProviderSuite) TestAuthnRequestURL() {
	ar := s.sp.AuthnRequest()

	encoded, err := s.sp.EncodeAuthnRequest(ar)
	s.NoError(err)
	s.NotEmpty(encoded)

	u, err := s.sp.AuthnRequestURL(encoded, "somestate")
	s.NoError(err)
	s.Equal("http", u.Scheme)
	s.Equal("www.onelogin.net", u.Host)
	q := u.Query()
	s.Equal(encoded, q.Get("SAMLRequest"))
	s.Equal("somestate", q.Get("RelayState"))
}

func (s *ServiceProviderSuite) TestValidateResponse() {
	resp := saml.NewResponse(s.sp.IDPSSOURL, s.sp.IssuerURL, s.sp.AssertionConsumerServiceURL, "myuserid")
	x, err := resp.SignedString("/Response", s.privateKey, s.publicCert)
	s.NoError(err)

	parsedResp, err := saml.ParseResponse(x)
	s.NoError(err)

	err = s.sp.ValidateResponse(parsedResp)
	s.NoError(err)

	s.Equal("myuserid", parsedResp.Assertion.Subject.NameID.Value)
}

func TestServiceProviderSuite(t *testing.T) {
	suite.Run(t, &ServiceProviderSuite{})
}

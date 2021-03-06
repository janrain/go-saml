package xmlsec

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// Sign signs an XML document
// `privateKeyPath` must be a path on the filesystem because xmlsec1 is
// run out of process through `exec`
func Sign(xml, privateKeyPath, idAttribute string) (string, error) {
	xmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(xmlsecInput.Name())
	xmlsecInput.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n")
	xmlsecInput.WriteString(xml)
	xmlsecInput.Close()

	xmlsecOutput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(xmlsecOutput.Name())
	xmlsecOutput.Close()

	output, err := exec.Command("xmlsec1", "--sign", "--privkey-pem", privateKeyPath,
		"--id-attr:ID", idAttribute,
		"--output", xmlsecOutput.Name(), xmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return "", errors.New(err.Error() + " : " + string(output))
	}

	signed, err := ioutil.ReadFile(xmlsecOutput.Name())
	if err != nil {
		return "", err
	}

	return strings.Trim(string(signed), "\n"), nil
}

// VerifySignature verifies the signature of a signed XML document
// `publicCertPath` and `trustedCertPaths` must be paths to a pem encoded cert
// on the filesystem because xmlsec1 is run out of process through `exec`
func VerifySignature(xml, publicCertPath string, trustedCertPaths []string, idAttribute string) error {
	xmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return err
	}

	xmlsecInput.WriteString(xml)
	xmlsecInput.Close()
	defer deleteTempFile(xmlsecInput.Name())

	args := []string{
		"--verify",
		"--pubkey-cert-pem",
		publicCertPath,
	}
	// add optional intermediate/root certs
	for _, p := range trustedCertPaths {
		args = append(args, "--trusted-pem", p)
	}
	args = append(args, "--id-attr:ID", idAttribute, xmlsecInput.Name())
	output, err := exec.Command("xmlsec1", args...).CombinedOutput()
	if err != nil {
		return errors.New("error verifying signature: " + err.Error() + ", " + string(output))
	}
	return nil
}

// deleteTempFile remove a file and ignore error
// Intended to be called in a defer after the creation of a temp file to ensure cleanup
func deleteTempFile(filename string) {
	_ = os.Remove(filename)
}

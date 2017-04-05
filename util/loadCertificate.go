package util

import (
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
)

// LoadCertificate from file system
func LoadCertificate(certPath string) (string, error) {
	data, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

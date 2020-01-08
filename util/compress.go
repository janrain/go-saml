package util

import (
	"bytes"
	"compress/flate"
	"io"
)

// Compress compresses
func Compress(in []byte) []byte {
	buf := new(bytes.Buffer)
	compressor, _ := flate.NewWriter(buf, 9)
	compressor.Write(in)
	compressor.Close()
	return buf.Bytes()
}

// Decompress decompresses
func Decompress(in []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	decompressor := flate.NewReader(bytes.NewReader(in))
	defer decompressor.Close()
	_, err := io.Copy(buf, decompressor)
	if err != nil {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}

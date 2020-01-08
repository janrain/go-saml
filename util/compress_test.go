package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompress(t *testing.T) {
	assert := assert.New(t)
	expected := []byte("This is the test string")
	compressed := Compress(expected)
	decompressed, err := Decompress(compressed)
	assert.NoError(err)
	assert.Equal(expected, decompressed)
	assert.True(len(compressed) > len(decompressed))
}

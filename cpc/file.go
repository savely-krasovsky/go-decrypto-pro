// CryptoPro Container package
package cpc

import (
	"encoding/asn1"
	"io/ioutil"
	"os"
	"path/filepath"
)

func ReadHeader(path string) (*Header, error) {
	headerKey, err := os.Open(filepath.Join(path, "header.key"))
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(headerKey)
	if err != nil {
		return nil, err
	}

	var h Header
	_, err = asn1.Unmarshal(b, &h)
	if err != nil {
		return nil, err
	}

	return &h, nil
}

func ReadPrimary(path, name string) (*Primary, error) {
	primaryKey, err := os.Open(filepath.Join(path, name))
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(primaryKey)
	if err != nil {
		return nil, err
	}

	var p Primary
	_, err = asn1.Unmarshal(b, &p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func ReadMasks(path, name string) (Masks, error) {
	masksKey, err := os.Open(filepath.Join(path, name))
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(masksKey)
	if err != nil {
		return nil, err
	}

	var m Masks
	_, err = asn1.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

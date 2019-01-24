package pkcs8

import (
	"encoding/asn1"
	"github.com/martinlindhe/gogost/gost3410"
	"go-decrypto-pro/util"
)

type pkcs8 struct {
	Version    int
	Algorithm  algorithmIdentifier
	PrivateKey asn1.RawValue
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters parameters
}

type parameters struct {
	Curve asn1.ObjectIdentifier
	Hash  asn1.ObjectIdentifier
}

func MarshalPrivateKey(key *gost3410.PrivateKey) ([]byte, error) {
	var privKey pkcs8

	privKey.Version = 0
	privKey.Algorithm = algorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19},
		Parameters: parameters{
			Curve: asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0},
			Hash:  asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 1},
		},
	}

	raw := key.Raw()
	if raw[len(raw)-1] >= 0x7f {
		raw = append(key.Raw(), 0x00)
	}
	util.Reverse(raw)

	// Encapsulating INTEGER into OCTET STRING
	b, err := asn1.Marshal(asn1.RawValue{Tag: 2, Bytes: raw})
	if err != nil {
		return nil, err
	}
	privKey.PrivateKey = asn1.RawValue{Tag: 4, Bytes: b}

	return asn1.Marshal(privKey)
}

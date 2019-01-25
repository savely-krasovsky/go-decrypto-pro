// CryptoPro Container package
package cpc

import "encoding/asn1"

type Header struct {
	KeyContainerContent struct {
		ContainerAlgorithmIdentifier asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		ContainerName                asn1.BitString        `asn1:"optional"`
		Attributes                   struct {
			Attributes                  asn1.BitString
			DH                          asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
			PrimaryPrivateKeyParameters struct {
				Curve asn1.ObjectIdentifier
				Hash  asn1.ObjectIdentifier
			}
		}
		Unknown3             asn1.RawValue `asn1:"optional"`
		Unknown4             asn1.RawValue `asn1:"optional"`
		BeginningOfPublicKey asn1.RawValue `asn1:"optional,tag:10"`
	}
	HMACKeyContainerContent []byte
}

type Primary struct {
	PrimaryKey   []byte
	SecondaryKey []byte `asn1:"optional"`
	HmacKey      []byte `asn1:"optional"`
}

type Masks [][]byte

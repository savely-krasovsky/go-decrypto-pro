package main // import "go-decrypto-pro"

import (
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/martinlindhe/gogost/gost28147"
	"github.com/martinlindhe/gogost/gost3410"
	"github.com/martinlindhe/gogost/gost341194"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
)

type Header struct {
	KeyContainerContent struct {
		ContainerAlgorithmIdentifier asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
		ContainerName                asn1.BitString        `asn1:"optional"`
		Attributes                   struct {
			Attributes asn1.BitString
			DH         asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
			Params     struct {
				Hash       asn1.ObjectIdentifier
				Encryption asn1.ObjectIdentifier
			}
		}
		Unknown3             asn1.RawValue
		Unknown4             asn1.RawValue
		BeginningOfPublicKey asn1.RawValue
	}
	HMACKeyContainerContent []byte
}

type Primary struct {
	PrimaryKey   []byte
	SecondaryKey []byte `asn1:"optional"`
	HMACKey      []byte `asn1:"optional"`
}

type Masks [][]byte

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

func main() {
	var (
		path string
	)

	flag.StringVar(&path, "path", "", "Container path")

	// Parse console arguments
	flag.Parse()

	// header
	header, err := ReadHeader(path)
	if err != nil {
		panic(err)
	}
	_ = header

	// primaries
	primary1, err := ReadPrimary(path, "primary.key")
	if err != nil {
		panic(err)
	}
	primary2, err := ReadPrimary(path, "primary.key")
	if err != nil {
		panic(err)
	}
	_ = primary2

	// masks
	masks1, err := ReadMasks(path, "masks.key")
	if err != nil {
		panic(err)
	}
	masks2, err := ReadMasks(path, "masks.key")
	if err != nil {
		panic(err)
	}
	_ = masks2

	derivedKey := DeriveKey(masks1[1], []byte(""))

	curve, err := gost3410.NewCurveFromParams(gost3410.CurveParamsGostR34102001CryptoProXchA)
	if err != nil {
		panic(err)
	}

	var key [32]byte
	copy(key[:], derivedKey)

	cipher := gost28147.NewCipher(key, &gost28147.Gost28147_CryptoProParamSetA)
	decrypter := cipher.NewECBDecrypter()
	primaryKey := make([]byte, 32)
	decrypter.CryptBlocks(primaryKey, primary1.PrimaryKey)

	// Reverse primary key
	for i, j := 0, len(primaryKey)-1; i < j; i, j = i+1, j-1 {
		primaryKey[i], primaryKey[j] = primaryKey[j], primaryKey[i]
	}
	pk := new(big.Int).SetBytes(primaryKey)

	// Reverse mask
	for i, j := 0, len(masks1[0])-1; i < j; i, j = i+1, j-1 {
		masks1[0][i], masks1[0][j] = masks1[0][j], masks1[0][i]
	}
	m := new(big.Int).SetBytes(masks1[0])

	raw := new(big.Int).Mod(
		new(big.Int).Mul(
			pk,
			new(big.Int).ModInverse(
				m,
				curve.Q,
			),
		),
		curve.Q,
	).Bytes()
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}

	privateKey, err := gost3410.NewPrivateKey(curve, gost3410.Mode2001, raw)
	if err != nil {
		panic(err)
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		panic(err)
	}

	fmt.Println(privateKey.Raw())
	fmt.Println(publicKey.Raw())
	fmt.Println(header.KeyContainerContent.BeginningOfPublicKey.Bytes)

	//x509.MarshalECPrivateKey()

	b, err := MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pem.EncodeToMemory(&pem.Block{
		Type: "GOST PRIVATE KEY",
		Bytes: b,
	})))
}

type pkcs8 struct {
	Version    int
	Algorithm  AlgorithmIdentifier
	PrivateKey asn1.RawValue
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters Parameters
}

type Parameters struct {
	Curve asn1.ObjectIdentifier
	Hash  asn1.ObjectIdentifier
}

func MarshalPKCS8PrivateKey(key *gost3410.PrivateKey) ([]byte, error) {
	var privKey pkcs8

	privKey.Version = 0

	privKey.Algorithm = AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19},
		Parameters: Parameters{
			Curve: asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0},
			Hash: asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 1},
		},
	}

	raw := append(key.Raw(), 0x00)
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}

	b, _ := asn1.Marshal(asn1.RawValue{Tag: 2, Bytes: raw})
	privKey.PrivateKey = asn1.RawValue{Tag: 4, Bytes: b}

	return asn1.Marshal(privKey)
}

func DeriveKey(salt, password []byte) []byte {
	// GOST R 34.11-94 - B=32b, L=32b
	// GOST R 34.11-256 - B=64b, L=32b
	// GOST R 34.11-512 - B=64b, L=64b
	b := 32

	// ???
	pin := make([]byte, len(password)*4)
	for i := 0; i < len(password); i++ {
		pin[i*4] = password[i]
	}

	hasher := gost341194.New(&gost28147.GostR3411_94_CryptoProParamSet)
	hasher.Write(salt)

	if len(password) != 0 {
		hasher.Write(pin)
	}

	hash := hasher.Sum(nil)
	hasher.Reset()

	c := []byte("DENEFH028.760246785.IUEFHWUIO.EF")
	s0 := make([]byte, b)
	s1 := make([]byte, b)

	iterations := 2
	if len(password) != 0 {
		iterations = 2000
	}

	for j := 0; j < iterations; j++ {
		for i := 0; i < b; i++ {
			s0[i] = c[i] ^ 0x36
			s1[i] = c[i] ^ 0x5C
		}

		hasher.Write(s0)
		hasher.Write(hash)
		hasher.Write(s1)
		hasher.Write(hash)

		c = hasher.Sum(nil)
		hasher.Reset()
	}
	for i := 0; i < b; i++ {
		s0[i] = c[i] ^ 0x36
		s1[i] = c[i] ^ 0x5C
	}

	hasher.Write(s0)
	hasher.Write(salt)
	hasher.Write(s1)
	if len(password) != 0 {
		hasher.Write(password)
	}

	c = hasher.Sum(nil)
	hasher.Reset()

	hasher.Write(c)

	return hasher.Sum(nil)
}

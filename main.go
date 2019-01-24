package main // import "go-decrypto-pro"

import (
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/martinlindhe/gogost/gost28147"
	"github.com/martinlindhe/gogost/gost3410"
	"github.com/martinlindhe/gogost/gost341194"
	"go-decrypto-pro/cpc"
	"go-decrypto-pro/pkcs8"
	"go-decrypto-pro/util"
	"math/big"
)

func main() {
	var (
		path       string
		passphrase string
	)

	flag.StringVar(&path, "path", "", "Container path")
	flag.StringVar(&passphrase, "pass", "", "Container passphrase")

	// Parse console arguments
	flag.Parse()

	// header
	header, err := cpc.ReadHeader(path)
	if err != nil {
		panic(err)
	}

	// primaries
	primary, err := cpc.ReadPrimary(path, "primary.key")
	if err != nil {
		panic(err)
	}

	// masks
	masks, err := cpc.ReadMasks(path, "masks.key")
	if err != nil {
		panic(err)
	}

	derivedKey, err := util.DeriveKey(gost341194.New(&gost28147.GostR3411_94_CryptoProParamSet), masks[1], []byte(passphrase))
	if err != nil {
		panic(err)
	}

	curve, err := gost3410.NewCurveFromParams(gost3410.CurveParamsGostR34102001CryptoProXchA)
	if err != nil {
		panic(err)
	}

	var key [32]byte
	copy(key[:], derivedKey)

	cipher := gost28147.NewCipher(key, &gost28147.Gost28147_CryptoProParamSetA)
	decrypter := cipher.NewECBDecrypter()
	primaryKey := make([]byte, 32)
	decrypter.CryptBlocks(primaryKey, primary.PrimaryKey)

	// Reverse primary key
	util.Reverse(primaryKey)
	pk := new(big.Int).SetBytes(primaryKey)

	// Reverse mask
	util.Reverse(masks[0])
	m := new(big.Int).SetBytes(masks[0])

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
	util.Reverse(raw)

	privateKey, err := gost3410.NewPrivateKey(curve, gost3410.Mode2001, raw)
	if err != nil {
		panic(err)
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		panic(err)
	}

	//fmt.Println(privateKey.Raw())
	//fmt.Println(publicKey.Raw())

	if bytes.HasPrefix(publicKey.Raw(), header.KeyContainerContent.BeginningOfPublicKey.Bytes) {
		b, err := pkcs8.MarshalPrivateKey(privateKey)
		if err != nil {
			panic(err)
		}

		fmt.Println(string(pem.EncodeToMemory(&pem.Block{
			Type:  "GOST PRIVATE KEY",
			Bytes: b,
		})))
	}
}

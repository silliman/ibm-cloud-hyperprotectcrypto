/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	grpc "google.golang.org/grpc"
)

//var callOpts = getCallOpts(cert, key, ca, address)

// Example_signAndVerifyUsingECDSAKeyPair generates an ECDSA key pair and uses the key pair to sign and verify data
// Flow: connect, generate ECDSA key pair, sign single-part data, verify single-part data
func signAndVerifyUsingECDSAKeyPair(srvrAddr, curve string) {
	var callOpts = getCallOpts(cert, key, ca, srvrAddr)
	conn, err := grpc.Dial(srvrAddr, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//ecParameters, err := asn1.Marshal(util.OIDNamedCurveP224)
	//ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	//ecParameters, err := asn1.Marshal(util.OIDNamedCurveP384)
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP521)
	fmt.Println("")

	switch curve {
	case "P224":
		fmt.Printf("selected curve %s with ObjectID of %v\n", curve, util.OIDNamedCurveP224)
		ecParameters, err = asn1.Marshal(util.OIDNamedCurveP224)
	case "P256":
		fmt.Printf("selected curve %s with ObjectID of %v\n", curve, util.OIDNamedCurveP256)
		ecParameters, err = asn1.Marshal(util.OIDNamedCurveP256)
	case "P384":
		fmt.Printf("selected curve %s with ObjectID of %v\n", curve, util.OIDNamedCurveP384)
		ecParameters, err = asn1.Marshal(util.OIDNamedCurveP384)
	case "P521":
		fmt.Printf("selected curve %s with ObjectID of %v\n", curve, util.OIDNamedCurveP521)
	default:
		fmt.Println("Invalid or unsupported curve specified, defaulting to P521")
		fmt.Printf("default curve P521 with ObjectID of %v\n", util.OIDNamedCurveP521)
	}

	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	fmt.Printf("Curve ObjectID in ASN.1 BER encoding is %v\n\n", ecParameters)

	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_VERIFY, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, true),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_SIGN, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	fmt.Println("Generated ECDSA PKCS key pair with mechanism ", ep11.CKM_EC_KEY_PAIR_GEN)

	//fmt.Printf("generate Key Pair Response is: %s\n\n", generateKeyPairStatus)

	fmt.Printf("\nkey pair public key blob length is %d bytes\n\n", len(generateKeyPairStatus.GetPubKey()))
	fmt.Printf("key pair public key blob is %v\n\n", generateKeyPairStatus.GetPubKey())
	fmt.Printf("key pair private key blob length is %d bytes\n\n", len(generateKeyPairStatus.GetPrivKey()))
	fmt.Printf("key pair private key blob is %v\n\n", generateKeyPairStatus.GetPrivKey())

	privKeyLen := len(generateKeyPairStatus.GetPrivKey())

	var mySlice []byte = generateKeyPairStatus.PrivKey[0:privKeyLen]

	fmt.Println("Some of the fields in the private key blob follow: ")
	//fmt.Printf("WK virtualization mask is %v\nSee 6.2.2 of page 179 of http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[:32])
	fmt.Printf("\nWK ID is %v\nSee 6.7.1 of page 182 of  http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[32:48])
	//fmt.Printf("Boolean attributes are %v\n", mySlice[48:56])
	//fmt.Printf("Mode identification is %v\n\n", mySlice[56:64])
	fmt.Printf("Blob version is %v\nSee 3.1.1 on page 141 of http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[64:66])
	fmt.Printf("IV is %v\n\n", mySlice[66:80])
	fmt.Printf("Encrypted part is %v\n\n", mySlice[80:privKeyLen-32])
	fmt.Printf("MAC is %v\nMAC is 32 bytes, see field 15 in 3.1 on page 140 of http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[privKeyLen-32:])

	pemBlock := &pem.Block{
		Type:  "HSM ENCRYPTED PRIVATE KEY",
		Bytes: generateKeyPairStatus.PrivKey,
	}
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		panic(fmt.Errorf("Failed to encode Private EC Key: %s", err))
	}

	fmt.Println("")

	pemBlock = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: generateKeyPairStatus.GetPubKey(),
	}
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		panic(fmt.Errorf("Failed to encode Public EC Key: %s", err))
	}

	fmt.Println("")

	// Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairStatus.PrivKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}

	signData := sha256.New().Sum([]byte("This data needs to be signed and verified!"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairStatus.PubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}

	//signData = sha256.New().Sum([]byte("This data needs to be signed!"))
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Signature verified")

}

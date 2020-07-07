/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	uuid "github.com/satori/go.uuid"
	grpc "google.golang.org/grpc"
)

// Example_wrapAndUnWrapKey wraps an AES key with a RSA public key and then unwraps it with the private key
// Flow: connect, generate AES key, generate RSA key pair, wrap/unwrap AES key with RSA key pair
func wrapAndUnwrapKey(wrapAllowed, unwrapAllowed bool) {
	var callOpts = getCallOpts(cert, key, ca, address)
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	// Generate a AES key
	desKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(256/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, true), // must be true to be wrapped
	)
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: desKeyTemplate,
		KeyId:    uuid.NewV4().String(), // optional
	}
	generateNewKeyStatus, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generate AES key error: %s", err))
	} else {
		fmt.Println("Generated AES key")
	}

	// Generate RSA key pairs
	publicExponent := []byte{0x11}
	publicKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_WRAP, wrapAllowed), // to wrap a key
		util.NewAttribute(ep11.CKA_MODULUS_BITS, uint64(2048)),
		util.NewAttribute(ep11.CKA_PUBLIC_EXPONENT, publicExponent),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_PRIVATE, true),
		util.NewAttribute(ep11.CKA_SENSITIVE, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_UNWRAP, unwrapAllowed), // to unwrap a key
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyTemplate,
		PrivKeyTemplate: privateKeyTemplate,
		PrivKeyId:       uuid.NewV4().String(),
		PubKeyId:        uuid.NewV4().String(),
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}
	fmt.Println("Generated PKCS RSA key pair")

	fmt.Printf("\nthe AES key prior to being wrapped is:\n%v\n\n", generateNewKeyStatus.Key)
	fmt.Printf("the checksum of the AES key is: %v\n\n", generateNewKeyStatus.GetCheckSum()[:3])

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:  generateKeyPairStatus.PubKey,
		Key:  generateNewKeyStatus.Key,
	}
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}
	fmt.Println("the AES key has been wrapped with a PKCS RSA Public Key")

	desUnwrapKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_CLASS, ep11.CKO_SECRET_KEY),
		util.NewAttribute(ep11.CKA_KEY_TYPE, ep11.CKK_AES),
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(128/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		//util.NewAttribute(ep11.CKA_EXTRACTABLE, false), // must be true to be wrapped
	)
	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:      generateKeyPairStatus.PrivKey,
		Wrapped:  wrapKeyResponse.Wrapped,
		Template: desUnwrapKeyTemplate,
	}
	unWrappedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap AES key error: %s", err))
	}
	if !bytes.Equal(generateNewKeyStatus.GetCheckSum()[:3], unWrappedResponse.GetCheckSum()[:3]) {
		panic(fmt.Errorf("Unwrap AES key has a different checksum than the original key"))
	} else {
		fmt.Println("The AES key has been unwrapped with the PKCS Private Key corresponding to the PKCS Public Key we used to wrap it with.")
	}

	fmt.Printf("\nthe AES key after being wrapped and unwrapped is:\n%v\n\n", unWrappedResponse.GetUnwrapped())
	fmt.Printf("the checksum of the unwrapped AES key is: %v\n\n", unWrappedResponse.GetCheckSum())

	// Output:
	// Generated AES key
	// Generated PKCS key pair
	// Wrapped AES key
	// Unwrapped AES key
}

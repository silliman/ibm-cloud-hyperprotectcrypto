/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	uuid "github.com/satori/go.uuid"
	grpc "google.golang.org/grpc"
)

// encryptAndDecrypt encrypts and decrypts plain text
// Flow: connect, generate AES key, generate IV, encrypt multi-part data, decrypt multi-part data

func encryptAndDecrypt(srvrAddr string, keyLen int, textToEncrypt string) {
	var callOpts = getCallOpts(cert, key, ca, srvrAddr)

	conn, err := grpc.Dial(srvrAddr, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	keyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(keyLen/8)),
		util.NewAttribute(ep11.CKA_WRAP, false),
		util.NewAttribute(ep11.CKA_UNWRAP, false),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false), // set to false!
		util.NewAttribute(ep11.CKA_TOKEN, true),        // ignored by EP11
	)

	keygenmsg := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: keyTemplate,
		KeyId:    uuid.NewV4().String(), // optional
	}

	generateKeyStatus, err := cryptoClient.GenerateKey(context.Background(), keygenmsg)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key with mechanism ", ep11.CKM_AES_KEY_GEN)
	fmt.Printf("\nlength of key blob is %d bytes\n", len(generateKeyStatus.Key))
	//fmt.Printf("generateKeyStatus is %v\n,type is %T\n", generateKeyStatus, generateKeyStatus)
	fmt.Println("Key blob is (values in decimal):")
	fmt.Printf("%v\n\n", generateKeyStatus.GetKey())
	fmt.Println("The above structure is what you would save in order to persist this key blob.")
	fmt.Println("")
	fmt.Println("Below is how the above structure would typically be saved, in PEM Format:\n ")
	pemBlock := &pem.Block{
		Type:  "HSM ENCRYPTED AES SECRET KEY",
		Bytes: generateKeyStatus.GetKey(),
	}
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		panic(fmt.Errorf("Failed to encode AES Key: %s", err))
	}

	var mySlice []byte = generateKeyStatus.Key[0:256]

	fmt.Printf("\nWK virtualization mask is %v\nSee 6.2.2 of page 179 of http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[:32])
	fmt.Printf("WK ID is %v\nSee 6.7.1 on page 182 of  http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[32:48])
	//fmt.Printf("Boolean attributes are %v\n", mySlice[48:56])
	//fmt.Printf("Mode identification is %v\n\n", mySlice[56:64])
	fmt.Printf("Blob version is %v\nSee 3.1.1 on page 141 of http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[64:66])
	fmt.Printf("Initialization Vector is %v\n\n", mySlice[66:80])
	fmt.Printf("Encrypted part is %v\n\n", mySlice[80:len(generateKeyStatus.GetKey())-32])
	fmt.Printf("MAC is %v\nMAC is 32 bytes, see field 15 in 3.1 on page 140 of http://public.dhe.ibm.com/security/cryptocards/pciecc4/EP11/docs/ep11-structure.pdf\n\n", mySlice[len(generateKeyStatus.GetKey())-32:])
	fmt.Printf("Checksum is %v, length of checksum is %d\n\n", generateKeyStatus.GetCheckSum(), len(generateKeyStatus.CheckSum))

	//fmt.Println("")
	//fmt.Println(generateKeyStatus.String())
	fmt.Println("")
	//fmt.Printf("\ngenerateKeyStatus.Key is %v \n\n", generateKeyStatus.Key)

	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	//fmt.Println("Generated IV")

	encipherInitInfo := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Key:  generateKeyStatus.Key, // you may want to store this
	}

	//fmt.Printf("generateKeyStatus.Key is %v \n", generateKeyStatus.Key)

	cipherStateInit, err := cryptoClient.EncryptInit(context.Background(), encipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptInit [%s]", err))
	}

	plain := []byte(textToEncrypt)
	fmt.Printf("Original message, prior to any encryption or decryption operations:  %s\n\n", plain)

	encipherDataUpdate := &pb.EncryptUpdateRequest{
		State: cipherStateInit.State,
		Plain: plain[:20],
	}
	encipherStateUpdate, err := cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext := encipherStateUpdate.Ciphered[:]
	fmt.Println("in progress ciphertext is:")
	fmt.Printf("%s\n\n", ciphertext)
	encipherDataUpdate = &pb.EncryptUpdateRequest{
		State: encipherStateUpdate.State,
		Plain: plain[20:],
	}
	encipherStateUpdate, err = cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateUpdate.Ciphered...)
	fmt.Println("in progress ciphertext is:")
	fmt.Printf("%s\n\n", ciphertext)
	encipherDataFinal := &pb.EncryptFinalRequest{
		State: encipherStateUpdate.State,
	}
	encipherStateFinal, err := cryptoClient.EncryptFinal(context.Background(), encipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptFinal [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateFinal.Ciphered...)
	fmt.Println("Final ciphertext is:")
	fmt.Printf("%s\n\n", ciphertext)
	//fmt.Println("Encrypted message")

	decipherInitInfo := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Key:  generateKeyStatus.Key, // you may want to store this
	}

	//fmt.Printf("generateKeyStatus.Key is %v \n", generateKeyStatus.Key)

	decipherStateInit, err := cryptoClient.DecryptInit(context.Background(), decipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptInit [%s]", err))
	}

	decipherDataUpdate := &pb.DecryptUpdateRequest{
		State:    decipherStateInit.State,
		Ciphered: ciphertext[:16],
	}
	decipherStateUpdate, err := cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}

	plaintext := decipherStateUpdate.Plain[:]
	fmt.Println("In progress decryption is:")
	fmt.Printf("%s\n\n", plaintext)

	decipherDataUpdate = &pb.DecryptUpdateRequest{
		State:    decipherStateUpdate.State,
		Ciphered: ciphertext[16:],
	}
	decipherStateUpdate, err = cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}
	plaintext = append(plaintext, decipherStateUpdate.Plain...)
	fmt.Println("In progress decryption is:")
	fmt.Printf("%s\n\n", plaintext)

	decipherDataFinal := &pb.DecryptFinalRequest{
		State: decipherStateUpdate.State,
	}
	decipherStateFinal, err := cryptoClient.DecryptFinal(context.Background(), decipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptFinal [%s]", err))
	}
	plaintext = append(plaintext, decipherStateFinal.Plain...)
	fmt.Println("Final decryption is:")
	fmt.Printf("%s\n\n", plaintext)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single"))
	} else {
		fmt.Println("Original message equals decrypted message!")
	}

	fmt.Printf("\nOriginal message:  %s\n", plain)
	fmt.Printf("Length of original message: %d\n", len(plain))
	fmt.Println("\nEncrypted message")
	fmt.Printf("%s\n", ciphertext)
	fmt.Printf("Length of encrypted message: %d\n", len(ciphertext))
	fmt.Printf("\nDecrypted message: %s\n", plaintext)
	fmt.Printf("Length of decrypted message: %d\n", len(plaintext))

}

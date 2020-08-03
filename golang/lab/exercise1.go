/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"fmt"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	grpc "google.golang.org/grpc"
)

// Example_getMechanismInfo retrieves a mechanism list and retrieves detailed information for the CKM_RSA_PKCS mechanism
// Flow: connect, get mechanism list, get mechanism info
func getMechanismInfo(srvrAddr string) {
	var callOpts = getCallOpts(cert, key, ca, srvrAddr)
	conn, err := grpc.Dial(srvrAddr, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	mechanismListRequest := &pb.GetMechanismListRequest{}
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), mechanismListRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism list error: %s", err))
	}
	fmt.Printf("Got mechanism list of length %d:\n\n", len(mechanismListResponse.Mechs))
	/*for _, v := range mechanismListResponse.Mechs {
		fmt.Println(v)
	}*/

	for i, v := range mechanismListResponse.Mechs {
		mechanismInfoRequest := &pb.GetMechanismInfoRequest{
			Mech: v,
		}
		mechanismInfoResponse, err := cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
		if err != nil {
			panic(fmt.Errorf("Get mechanism info error: %s", err))
		} else {
			fmt.Println("Mechanism ", i, ":", v, "\n", mechanismInfoResponse.GetMechInfo(), "\n ")
		}
	}

	mechanismInfoRequest := &pb.GetMechanismInfoRequest{
		Mech: ep11.CKM_RSA_PKCS,
	}
	_, err = cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism info error: %s", err))
	}

	// Output:
	// Got mechanism list:
	// [CKM_RSA_PKCS] ...
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
)

// The following IBM Cloud items need to be changed prior to running the sample program

const address = "192.168.22.80:9876"
const cert = "../certs/client.pem"
const key = "../certs/client-key.pem"
const ca = "../certs/ca.pem"

func getCallOpts(cert, key, ca, address string) []grpc.DialOption {
	certificate, _ := tls.LoadX509KeyPair(cert, key)
	cacert, _ := ioutil.ReadFile(ca)
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cacert)
	callOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName:   address,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certPool,
		})),
	}
	return callOpts
}

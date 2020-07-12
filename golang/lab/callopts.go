package main

import (
	"crypto/tls"
	"crypto/x509"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
)

/*
   address constant is the IP address and port on which the GREP11 server is listening

   cert constant is the Client certificate which is presented to the GREP11 server during TLS handshake

   key constant is the Client private key which the client keeps private, but it is used during TLS handshake

   ca constant is the certification authority certificate- the client expects the GREP11 server to present
    a certificate that is signed and issued by this certification authority.  (The GREP11 server expects the
    same from the certificate the client presents to it).
*/

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

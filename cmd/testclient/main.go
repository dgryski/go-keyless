package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/dgryski/go-keyless"
	"io/ioutil"
	"log"
	"strconv"
)

func main() {

	port := flag.Int("port", 0, "port to connect to")
	clientCert := flag.String("client-cert", "", "client certificate file")
	clientKey := flag.String("client-key", "", "client key")
	caFile := flag.String("ca-file", "", "ca file")
	server := flag.String("server", "", "server")

	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		log.Fatalln("unable to load private key:", err)
	}

	caCert, err := ioutil.ReadFile(*caFile)
	if err != nil {
		log.Fatalln("unable to load CA:", err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCert)
	if !ok {
		log.Fatalln("failed to load CAs")
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, InsecureSkipVerify: true}
	remote := *server + ":" + strconv.Itoa(*port)
	log.Printf("remote %+v\n", remote)
	conn, err := keyless.Dial(remote, &config)

	if err != nil {
		log.Fatalf("dial error: %s", err)
	}

	for i := 0; i < 10; i++ {
		items, err := conn.Ping([]byte("hello, world"))
		fmt.Println(items, err)
	}

}

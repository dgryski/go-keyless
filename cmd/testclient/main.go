package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
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

	config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots}
	remote := *server + ":" + strconv.Itoa(*port)
	log.Printf("remote %+v\n", remote)
	conn, err := tls.Dial("tcp", remote, &config)

	if err != nil {
		log.Fatalf("dial error: %s", err)
	}

	var h keyless.Header

	h.VersionMaj = keyless.VersionMaj
	h.ID = 0x12345678
	h.Items = []keyless.Item{
		{Tag: keyless.TagOPCODE, Data: []byte{keyless.OpPing}},
		{Tag: keyless.TagPayload, Data: nil},
	}

	b, _ := keyless.Marshal(h)

	log.Printf("b\n%s", hex.Dump(b))

	_, err = conn.Write(b)
	if err != nil {
		log.Fatalf("write: %#vv\n", err)
	}

	var response [1024]byte

	conn.Read(response[:])

	log.Printf("response\n%s", hex.Dump(response[:]))
}

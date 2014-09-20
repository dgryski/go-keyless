package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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

	config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, InsecureSkipVerify: true}
	remote := *server + ":" + strconv.Itoa(*port)
	log.Printf("remote %+v\n", remote)
	conn, err := tls.Dial("tcp", remote, &config)

	if err != nil {
		log.Fatalf("dial error: %s", err)
	}

	var p keyless.Packet

	p.VersionMaj = keyless.VersionMaj
	p.ID = 0x12345678
	p.Items = []keyless.Item{
		{Tag: keyless.TagOPCODE, Data: []byte{keyless.OpPing}},
		{Tag: keyless.TagPayload, Data: []byte("hello, world")},
	}

	b, _ := keyless.Marshal(p)

	_, err = conn.Write(b)
	if err != nil {
		log.Fatalf("write: %#vv\n", err)
	}

	var header [8]byte

	conn.Read(header[:])

	rlen := binary.BigEndian.Uint16(header[2:])

	response := make([]byte, (rlen + 8))
	copy(response, header[:])

	conn.Read(response[8:])

	var r keyless.Packet
	keyless.Unmarshal(response[:], &r)

	log.Printf("response\n%#v", r)
}

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
	privateKey := flag.String("private-key", "", "server's private key")

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

	pkeyData, err := ioutil.ReadFile(*privateKey)
	if err != nil {
		log.Fatal("unable to load private key:", err)
	}
	block, _ := pem.Decode(pkeyData)

	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalln("unable to parse private key", err)
	}

	out, err := rsa.EncryptPKCS1v15(rand.Reader, &pkey.PublicKey, []byte("hello, world"))
	if err != nil {
		log.Fatalln("unable to encrypt:", err)
	}

	digest := keyless.DigestPublicModulus(&pkey.PublicKey)

	items, err := conn.Decrypt(digest[:], out)

	fmt.Printf("string(items[1].Data) %+v\n", string(items[1].Data))

	hashed := sha256.Sum256([]byte("hello, world"))

	sig, err := rsa.SignPKCS1v15(rand.Reader, pkey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalln("unable to encrypt:", err)
	}

	items, err = conn.Sign(digest[:], keyless.OpRSASignSHA256, hashed[:])

	if !bytes.Equal(sig, items[1].Data) {
		log.Fatalln("signature mismatch")
	}
}

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
	"net"
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
		r, err := conn.Ping(&keyless.Params{Payload: []byte("hello, world")})
		fmt.Println(r, err)
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

	netIP := net.ParseIP("8.8.8.8")

	plain, err := conn.Decrypt(&keyless.Params{Digest: digest[:], Payload: out, ClientIP: netIP})

	fmt.Printf("string(plain) %+v, err=%v\n", string(plain), err)

	hashed := sha256.Sum256([]byte("hello, world"))

	sig, err := rsa.SignPKCS1v15(rand.Reader, pkey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalln("unable to encrypt:", err)
	}

	remotesig, err := conn.Sign(keyless.OpRSASignSHA256, &keyless.Params{Digest: digest[:], Payload: hashed[:]})
	fmt.Println("signature match", bytes.Equal(sig, remotesig), "err=", err)

	digest[0]++

	remotesig, err = conn.Sign(keyless.OpRSASignSHA256, &keyless.Params{Digest: digest[:], Payload: hashed[:]})
	fmt.Println("expect failure: notfound err=", err)

	// test pipelining
	start := make(chan bool)
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			<-start
			conn.Ping(nil)
			done <- true
		}()
	}
	close(start)

	for i := 0; i < 10; i++ {
		<-done
	}

	conn.Close()
}

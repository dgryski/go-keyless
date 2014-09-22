package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dgryski/go-keyless"
)

func handleRequests(conn io.ReadWriteCloser, keys map[[32]byte]*rsa.PrivateKey) {

	defer conn.Close()

	for {

		var header [8]byte

		// FIXME(dgryski): need another timeout on these reads
		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			// partial read -- unknown connection state
			break
		}

		rlen := binary.BigEndian.Uint16(header[2:])

		response := make([]byte, rlen+8)
		copy(response, header[:])

		_, err = io.ReadFull(conn, response[8:])
		if err != nil {
			// partial read -- unknown connection state
			break
		}

		p, op, params, err := keyless.UnpackRequest(response)
		if err != nil {
			sendErrorResponse(conn, p, err.(keyless.ErrCode))
			continue
		}

		switch op {
		case keyless.OpPing:
			b := keyless.PackRequest(p.ID, keyless.OpPong, params)
			conn.Write(b)

		case keyless.OpRSADecrypt:
			var digest [32]byte
			if len(params.Digest) != 32 {
				sendErrorResponse(conn, p, keyless.ErrKeyNotFound)
				continue
			}
			copy(digest[:], params.Digest)
			key, ok := keys[digest]
			if !ok {
				sendErrorResponse(conn, p, keyless.ErrKeyNotFound)
				continue
			}

			out, err := rsa.DecryptPKCS1v15(rand.Reader, key, params.Payload)
			if err != nil {
				sendErrorResponse(conn, p, keyless.ErrCryptoFailed)
				continue
			}

			b := keyless.PackRequest(p.ID, keyless.OpResponse, &keyless.Params{Payload: out})
			conn.Write(b)

		case keyless.OpRSASignMD5SHA1,
			keyless.OpRSASignSHA1,
			keyless.OpRSASignSHA224,
			keyless.OpRSASignSHA256,
			keyless.OpRSASignSHA384,
			keyless.OpRSASignSHA512:
			if len(params.Digest) != 32 {
				sendErrorResponse(conn, p, keyless.ErrKeyNotFound)
				continue
			}
			var digest [32]byte
			copy(digest[:], params.Digest)
			key, ok := keys[digest]
			if !ok {
				sendErrorResponse(conn, p, keyless.ErrKeyNotFound)
				continue
			}

			h := keyless.OpToHash(op)

			out, err := rsa.SignPKCS1v15(rand.Reader, key, h, params.Payload)
			if err != nil {
				sendErrorResponse(conn, p, keyless.ErrCryptoFailed)
				continue
			}

			b := keyless.PackRequest(p.ID, keyless.OpResponse, &keyless.Params{Payload: out})
			conn.Write(b)

		default:
			sendErrorResponse(conn, p, keyless.ErrBadOpcode)
		}
	}
}

func sendErrorResponse(conn io.ReadWriteCloser, p *keyless.Packet, errcode keyless.ErrCode) {
	b := keyless.PackRequest(p.ID, keyless.OpError, &keyless.Params{Payload: []byte{byte(errcode)}})
	conn.Write(b)
}

func main() {

	port := flag.Int("port", 2048, "listen port")
	keydir := flag.String("private-key-directory", "", "directory storing private keys")
	/*
		serverCert := flag.String("server-cert", "", "server certificate")
		serverKey := flag.String("server-key", "", "server key")
		caCert := flag.String("ca-cert", "", "ca certificate")
	*/

	flag.Parse()

	keys := make(map[[32]byte]*rsa.PrivateKey)

	// load all private keys
	filepath.Walk(*keydir, func(path string, info os.FileInfo, err error) error {
		log.Println("walking", path)
		if info.IsDir() {
			return nil
		}

		if err != nil {
			return err
		}

		pkeyData, err := ioutil.ReadFile(path)
		if err != nil {
			log.Println("error reading key", path, ", skipping")
			return nil
		}
		block, _ := pem.Decode(pkeyData)

		pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Println("error parsing key", path, ", skipping")
			return nil
		}

		digest := keyless.DigestPublicModulus(&pkey.PublicKey)
		keys[digest] = pkey

		return nil
	})

	if len(keys) == 0 {
		log.Fatal("no private keys loaded")
	}

	ln, e := net.Listen("tcp", ":"+strconv.Itoa(*port))
	if e != nil {
		log.Fatal("listen error:", e)
	}

	log.Println("tcp server starting")

	for {
		lconn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go handleRequests(lconn, keys)
	}
}

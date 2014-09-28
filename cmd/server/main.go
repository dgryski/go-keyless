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
	"sync"

	"github.com/dgryski/go-keyless"
)

type lockedWriter struct {
	io.WriteCloser
	sync.Mutex
	Err error
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.Lock()
	n, e := l.WriteCloser.Write(b)
	if e != nil {
		if l.Err == nil {
			l.Err = e
		}

		l.Close()
	}
	l.Unlock()
	return n, e
}

func handleRequests(conn io.ReadWriteCloser, keys map[[32]byte]*rsa.PrivateKey) {

	defer conn.Close()
	lwriter := &lockedWriter{WriteCloser: conn}

	for {

		var header [8]byte

		// FIXME(dgryski): need another timeout on these reads
		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			log.Println("error reading header:", err)

			// partial read -- unknown connection state
			break
		}

		rlen := binary.BigEndian.Uint16(header[2:])

		response := make([]byte, rlen+8)
		copy(response, header[:])

		_, err = io.ReadFull(conn, response[8:])
		if err != nil {
			log.Println("error reading body:", err)
			// partial read -- unknown connection state
			break
		}

		go func() {

			p, op, params, err := keyless.UnpackRequest(response)
			if err != nil {
				writeErrorResponse(conn, p, op, err.(keyless.ErrCode), err, params)
				return
			}

			defer func() {
				if r := recover(); r != nil {
					writeErrorResponse(lwriter, p, op, keyless.ErrInternal, nil, params)
				}
			}()

			switch op {
			case keyless.OpPing:
				b := keyless.PackRequest(p.ID, keyless.OpPong, params)
				lwriter.Write(b)

			case keyless.OpRSADecrypt:

				key := getPrivateKey(keys, params.Digest)
				if key == nil {
					writeErrorResponse(lwriter, p, op, keyless.ErrKeyNotFound, nil, params)
					break
				}

				out, err := rsa.DecryptPKCS1v15(rand.Reader, key, params.Payload)
				if err != nil {
					writeErrorResponse(lwriter, p, op, keyless.ErrCryptoFailed, err, params)
					break
				}

				b := keyless.PackRequest(p.ID, keyless.OpResponse, &keyless.Params{Payload: out})
				lwriter.Write(b)

			case keyless.OpRSASignMD5SHA1,
				keyless.OpRSASignSHA1,
				keyless.OpRSASignSHA224,
				keyless.OpRSASignSHA256,
				keyless.OpRSASignSHA384,
				keyless.OpRSASignSHA512:

				key := getPrivateKey(keys, params.Digest)
				if key == nil {
					writeErrorResponse(lwriter, p, op, keyless.ErrKeyNotFound, err, params)
					break
				}

				h := keyless.OpToHash(op)

				out, err := rsa.SignPKCS1v15(rand.Reader, key, h, params.Payload)
				if err != nil {
					writeErrorResponse(lwriter, p, op, keyless.ErrCryptoFailed, err, params)
					break
				}

				b := keyless.PackRequest(p.ID, keyless.OpResponse, &keyless.Params{Payload: out})
				lwriter.Write(b)
			default:
				writeErrorResponse(lwriter, p, op, keyless.ErrBadOpcode, nil, params)
			}
		}()
	}
}

func writeErrorResponse(conn io.Writer, p *keyless.Packet, op keyless.OpCode, errcode keyless.ErrCode, err error, params *keyless.Params) (int, error) {
	log.Printf("%s: %08x: %s: %x: %s: %v", params.ClientIP, p.ID, op, params.Digest, errcode, err)
	b := keyless.PackRequest(p.ID, keyless.OpError, &keyless.Params{Payload: []byte{byte(errcode)}})
	return conn.Write(b)
}

func getPrivateKey(keys map[[32]byte]*rsa.PrivateKey, paramDigest []byte) *rsa.PrivateKey {
	var digest [32]byte
	if len(paramDigest) != 32 {
		return nil
	}
	copy(digest[:], paramDigest)
	return keys[digest]
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

		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
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

		log.Printf("loaded %s: %x", path, digest)

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

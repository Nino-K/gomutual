package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	rootFilePath := os.Getenv("ROOT_CA")
	if rootFilePath == "" {
		log.Fatalf("root cert must be provided")
	}
	rootCert, err := ioutil.ReadFile(filepath.Join(rootFilePath, "root.crt"))
	if err != nil {
		log.Fatalf("error reading rootCert: %v", err)
	}
	rootKey, err := ioutil.ReadFile(filepath.Join(rootFilePath, "root.key"))
	if err != nil {
		log.Fatalf("error reading rootKey: %v", err)
	}

	crtBlock, _ := pem.Decode(rootCert)
	if crtBlock == nil {
		log.Fatalf("error decoding crtBlock")
	}

	rootCrtPEM, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		log.Fatalf("error parsing certificate")
	}
	keyBlock, _ := pem.Decode(rootKey)
	if crtBlock == nil {
		log.Fatalf("error decoding keyBlock")
	}

	rootKeyPem, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		log.Fatalf("error parsing key: %v", err)
	}

	// create a key-pair for the client
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	// create a template for the client
	clientCertTmpl, err := CertTemplate()
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}
	clientCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	clientCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// the root cert signs the cert by again providing its private key
	_, clientCertPEM, err := CreateCert(clientCertTmpl, rootCrtPEM, &clientKey.PublicKey, rootKeyPem)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}

	// encode and load the cert and private key for the client
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})
	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		log.Fatalf("invalid key pair: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(crtBlock.Bytes)
	authedClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            certPool,
				Certificates:       []tls.Certificate{clientTLSCert},
				InsecureSkipVerify: true,
			},
		},
	}
	_, err = authedClient.Get("https://127.0.0.1:4443")
	if err != nil {
		log.Fatalf("error client: %v", err)
	}
}

func CreateCert(template, parent *x509.Certificate, pub, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	//PEM encoded cert (standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

// helper func to crate cert template with a serial number and other fields
func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Ninoski, Inc."}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}
	return &tmpl, nil

}

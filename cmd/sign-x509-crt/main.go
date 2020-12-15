// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"path/filepath"
	"time"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/pkcs11"
)

var cfg string
var validityDays uint64
var csrPath string
var caPath string
var certOutPath string

func parseFlags(){
	flag.StringVar(&cfg, "config", "", "CA key configuration file")
	flag.Uint64Var(&validityDays, "days", 720, "validity period in days")
	flag.StringVar(&caPath, "cacert", "", "path to CA cert")
	flag.StringVar(&csrPath, "in", "", "csrPath file path")
	flag.StringVar(&certOutPath, "out", "", "the output path of signed cert")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if cfg == "" {
		log.Fatal("no signing configuration file specified")
	}

	if caPath == "" {
		log.Fatal("no ca cert path specified")
	}

	if csrPath == "" {
		log.Fatal("no csrPath file specified")
	}

	if certOutPath == "" {
		certOutPath = fmt.Sprintf("%s.%s", csrPath[:len(csrPath) - len(filepath.Ext(csrPath))], "crt")
	}
}

func constructUnsignedX509Cert() *x509.Certificate {
	csrData, err := ioutil.ReadFile(csrPath)
	if err != nil {
		log.Fatalf("failed to read csrPath file: %v", err)
	}

	csrBlock, _ := pem.Decode(csrData)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		log.Fatalf("failed to parse cert request: %v", err)
	}

	start := uint64(time.Now().Unix())
	end := start + validityDays * 3600 * 24
	start -= 3600

	return &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          newSerial(),
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Unix(int64(start), 0),
		NotAfter:              time.Unix(int64(end), 0),
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func newSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}

func main() {
	parseFlags()

	cfgData, err := ioutil.ReadFile(cfg)
	if err != nil {
		log.Fatal(err)
	}
	cc := &crypki.CAConfig{}
	if err := json.Unmarshal(cfgData, cc); err != nil {
		log.Fatal(err)
	}

	// x509 requires CA certs.
	requireX509CACert := map[string]bool{
		cc.Identifier: true,
	}

	signer, err := pkcs11.NewCertSign(cc.PKCS11ModulePath, []config.KeyConfig{{
		Identifier:             cc.Identifier,
		SlotNumber:             uint(cc.SlotNumber),
		UserPinPath:            cc.UserPinPath,
		KeyLabel:               cc.KeyLabel,
		SessionPoolSize:        2,
		X509CACertLocation:     caPath,
		CreateCACertIfNotExist: false,
	}}, requireX509CACert, "", nil) // hostname and ips are not required when the CA cert is specified.

	if err != nil {
		log.Fatalf("unable to initialize cert signer: %v", err)
	}

	unsignedCert := constructUnsignedX509Cert()

	data, err := signer.SignX509Cert(unsignedCert, cc.Identifier)
	if err != nil {
		log.Fatalf("falied to sign x509 cert: %v", err)
	}

	if err := ioutil.WriteFile(certOutPath, data, 0644); err != nil {
		log.Printf("new signed cert generated, but unable to write to file %s: %v", certOutPath, err)
		log.Printf("cert generated: %q", certOutPath)
	} else {
		log.Printf("new x509 CA cert written to %s", certOutPath)
	}
}

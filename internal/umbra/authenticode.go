package umbra

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	"github.com/saferwall/pe"
	"go.mozilla.org/pkcs7"
)

//go:embed certs.pem
var certs []byte

var certPoolOnce = sync.OnceValue(func() *x509.CertPool {
	cp := x509.NewCertPool()

	var pemBlock *pem.Block
	rest := certs

	for {
		pemBlock, rest = pem.Decode(rest)
		if pemBlock == nil {
			break
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			panic(err)
		}

		cp.AddCert(cert)
	}

	return cp
})

func verifyAuthenticode(bytes []byte) error {
	// Need to enable SHA1 signatures for compatibility
	// Obviously not good, but it's better than the alternative of verifying nothing
	if err := os.Setenv("GODEBUG", "x509sha1=1"); err != nil {
		return err
	}

	// Would be preferable to use p.New where it mmaps the given file path
	// but building the full path wouldn't be necessarily confined to the afero.Fs
	pe, err := pe.NewBytes(bytes, &pe.Options{
		DisableCertValidation: true,
	})
	if err != nil {
		return err
	}

	if err := pe.Parse(); err != nil {
		return err
	}

	if len(pe.Certificates.Certificates) == 0 {
		return fmt.Errorf("no certificates found")
	}

	pkcs7, err := pkcs7.Parse(pe.Certificates.Raw)
	if err != nil {
		return err
	}

	if err := pkcs7.VerifyWithChainAtTime(certPoolOnce(), pe.Certificates.Certificates[0].Info.NotAfter); err != nil {
		return err
	}

	if !pe.Certificates.Certificates[0].SignatureValid {
		return fmt.Errorf("signature invalid")
	}

	return nil
}

package tls

import (
	"crypto/rsa"
	"github.com/scorpio-id/oauth/internal/config"
)

// GenerateTLSCertificate invokes PKI service to obtain a signed PKCS12 for configured DNS name (ex: oauth.ordinarycomputing.com)
func GenerateTLSCertificate(cfg *config.Config, private *rsa.PrivateKey) {
	// generate Kerberos TGT
	// submit Kerberos ST to PKI via SPNEGO
	// download and install PKCS12 (root + intermediate) 

	// add to PKI handlers: https://github.com/jcmturner/gokrb5/blob/master/USAGE.md#kerberised-service
}

func SerializeX509() {

}
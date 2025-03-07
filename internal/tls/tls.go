package tls

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/jcmturner/gokrb5/v8/client"
	kconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/scorpio-id/oauth/internal/config"
)

// RetrieveTLSCertificate invokes PKI service to obtain a signed PKCS12 for configured DNS name (ex: oauth.ordinarycomputing.com)
func RetrieveTLSCertificate(cfg config.Config) error {
	// read password from mounted volume using configured path
	kcfg, err := kconfig.Load("internal/config/krb5.conf")
	if err != nil {
		return err
	}

	// initialize Kerberos client and authenticate for TGT
	cl := client.NewWithPassword(cfg.SPNEGO.ServicePrincipalName, cfg.SPNEGO.Realm, cfg.SPNEGO.Password, kcfg)
	err = cl.Login()
	if err != nil {
		return err
	}

	defer cl.Destroy()

	// submit Kerberos ST to PKI via SPNEGO
	// build query parameters for PKCS12 HTTP request
	destination, err := url.Parse(cfg.PKI.Endpoint)
	if err != nil {
		return err
	}

	q := destination.Query()

	for _, san := range cfg.PKI.SANs {
		q.Add("san", san)
	}

	destination.RawQuery = q.Encode()

	fmt.Println("destination pki url: " + destination.String())

	r, _ := http.NewRequest("POST", destination.String(), nil)

	// TODO check if correct SPN 
	spnegocl := spnego.NewClient(cl, nil, cfg.PKI.ServicePrincipalName)
	response, err := spnegocl.Do(r)
	if err != nil {
		return err
	}

	fmt.Println("status: " + response.Status)

	// TODO read response and install PKCS12 (root + intermediate)

	return nil
}

func SerializeX509() {

}
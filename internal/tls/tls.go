package tls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/hetesiistvan/go-pkcs12"
	"github.com/jcmturner/gokrb5/v8/client"
	kconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/scorpio-id/oauth/internal/config"
)

// RetrieveTLSCertificate invokes PKI service to obtain a signed PKCS12 for configured DNS name (ex: oauth.ordinarycomputing.com)
func RetrieveTLSCertificate(cfg config.Config) ([]byte, error) {
	// read password from mounted volume using configured path
	kcfg, err := kconfig.Load("internal/config/krb5.conf")
	if err != nil {
		return nil, err
	}

	// initialize Kerberos client and authenticate for TGT
	cl := client.NewWithPassword(cfg.SPNEGO.ServicePrincipalName, cfg.SPNEGO.Realm, cfg.SPNEGO.Password, kcfg)
	err = cl.Login()
	if err != nil {
		return nil, err
	}

	defer cl.Destroy()

	// submit Kerberos ST to PKI via SPNEGO
	// build query parameters for PKCS12 HTTP request
	destination, err := url.Parse(cfg.PKI.Endpoint)
	if err != nil {
		return nil, err
	}

	q := destination.Query()

	for _, san := range cfg.PKI.SANs {
		q.Add("san", san)
	}

	destination.RawQuery = q.Encode()

	fmt.Println("destination pki url: " + destination.String())

	r, _ := http.NewRequest("POST", destination.String(), nil)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// disable SSL for SPNEGO
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	httpclient := &http.Client{Transport: customTransport}

	// TODO check if correct SPN 
	spnegocl := spnego.NewClient(cl, httpclient, "HTTP/ca.scorpio.ordinarycomputing.com")
	response, err := spnegocl.Do(r)
	if err != nil {
		return nil, err
	}

	fmt.Println("status: " + response.Status)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(body))

	return body, nil
}

func SerializePKCS12(content []byte, path string) error {
	// TODO check if password on .p12 file
	// TODO convert content []byte to .p12 file and save to filesystem
	// TODO remove underscore and install cacert as root certificate on filesystem
	key, cert, _, err := pkcs12.DecodeChain(content, "")
    if err != nil {
        return err
    }

	// store .cer file on provided filesystem path
	cout, err := os.Create(path + "/scorpio-oauth.crt")
    if err != nil {
        return err
    }

	defer cout.Close()

	w := bufio.NewWriter(cout)
	w.Write(cert.Raw)

	w.Flush()

	// store .cer file on provided filesystem path
	kout, err := os.Create(path + "/scorpio-oauth.key")
    if err != nil {
        return err
    }

	defer kout.Close()

	// FIXME might be incorrect way of converting interface to []byte
	w = bufio.NewWriter(kout)
	w.Write(key.([]byte))

	w.Flush()

	return nil
}
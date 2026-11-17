package config

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// Config provides a template for marshalling .yml configuration files
type Config struct {
	Server struct {
		Port string `yaml:"port" json:"port"`
		Host string `yaml:"host" json:"host"`
	} `yaml:"server" json:"server"`
	Persistence struct {
		Enabled  bool   `yaml:"enabled" json:"enabled"`
		Port     string `yaml:"port" json:"port"`
		Host     string `yaml:"host" json:"host"`
		User     string `yaml:"user" json:"user"`
		Path     string `yaml:"path" json:"path"`
		Password string `yaml:"-" json:"-"` // DO NOT MARSHAL PASSWORD!
		Database int    `yaml:"database" json:"database"`
	} `yaml:"persistence" json:"persistence"`
	OAuth struct {
		RSABits  int    `yaml:"rsa_bits" json:"rsa_bits"`
		Audience string `yaml:"audience" json:"audience"`
		Issuer   string `yaml:"issuer" json:"issuer"`
		TokenTTL string `yaml:"jwt_ttl" json:"jwt_ttl"`
		JWKS     string `yaml:"jwks" json:"jwks"`
	} `yaml:"oauth" json:"oauth"`
	SPNEGO struct {
		Realm                string `yaml:"realm" json:"realm"`
		ServicePrincipalName string `yaml:"service_principal_name" json:"service_principal_name"`
		Password             string `yaml:"password" json:"-"`
	} `yaml:"spnego" json:"spnego"`
	PKI struct {
		Endpoint             string   `yaml:"endpoint" json:"endpoint"`
		ServicePrincipalName string   `yaml:"service_principal_name" json:"service_principal_name"`
		SANs                 []string `yaml:"sans" json:"sans"`
	} `yaml:"pki" json:"pki"`
}

// NewConfig takes a .yml filename from the same /config directory, and returns a populated configuration
func NewConfig(s string) Config {
	f, err := os.Open(s)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)

	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	// TODO retrieve content from Kube Secrets using configured file paths if persistence enabled
	if cfg.Persistence.Enabled {
		content, err := os.ReadFile(cfg.Persistence.Path)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}

		cfg.Persistence.Password = string(content)
	}

	return cfg
}

func (conf *Config) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	// FIXME move CORS URLs to config
	// check CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "*")
        return
    }

	// return JSON representation of client id store
	w.Header().Set("Content-Type", "application/json")

	content, err := json.Marshal(conf)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	w.Write(content)
}
package data

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/redis/go-redis/v9"
	"github.com/scorpio-id/oauth/internal/config"
)

type Persistence struct {
	Client  *redis.Client
	Context context.Context
	cfg     config.Config
}

func NewPersistenceClient(cfg config.Config) Persistence {

	// FIXME: See if we can prevent Redis Options auto connect
	// TODO read documentation on rdb.Close() usage
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Persistence.Host + ":" + cfg.Persistence.Port,
		Username: cfg.Persistence.User,
		Password: cfg.Persistence.Password,
		DB:       cfg.Persistence.Database,
		// TODO enable TLS for redis >_>;
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	})

	// Test the connection with a Ping command
	// pong, err := rdb.Ping(context.Background()).Result()
	// if err != nil {
	// 	log.Fatalf("Failed to connect to Redis: %v", err)
	// }

	// TODO remove print statement!
	// fmt.Println("Connected to Redis! Response:", pong)

	// WARNING wiping DB for testing purposes ...
	// fmt.Println("Flushing DB for testing purposes ...")
	// err := rdb.FlushAll(context.Background()).Err()
	// if err != nil {
	//     fmt.Println("Failed to flush DB!")
	// }
	
	return Persistence{
		Client:  rdb,
		Context: context.Background(),
		cfg:     cfg,
	} 
}

func (persist *Persistence) SetSigningRSAKeyPair(private *rsa.PrivateKey) error {
	// convert RSA key pair into a PEM-encoded string
	bytes := x509.MarshalPKCS1PrivateKey(private)
	block := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: bytes,
		},
	)

	// store RSA key value pair
	err := persist.Client.Set(persist.Context, "rsa:", string(block), 0).Err()
	if err != nil {
		return err
	}

	return nil
}

func (persist *Persistence) GetSigningRSAKeyPair() (*rsa.PrivateKey, error) {
	result, err := persist.Client.Get(persist.Context, "rsa:").Result()
	if err != nil {
		return nil, err
	}

	// convert PEM-encoded string back into *rsa.PrivateKey interface
	block, _ := pem.Decode([]byte(result))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return private, nil
}

func (persist *Persistence) SetPKCS12(pfx []byte) error {

	err := persist.Client.Set(persist.Context, "pfx:", string(pfx), 0).Err()
	if err != nil {
		return err
	}

	return nil
}

func (persist *Persistence) GetPKCS12() ([]byte, error) {
	result, err := persist.Client.Get(persist.Context, "pfx:").Result()
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

func (persist *Persistence) SetClientID(cid ClientID) error {
	// marshal metadata struct to json and store with gob: https://stackoverflow.com/questions/53697507/save-generic-struct-to-redis
	result, err := json.Marshal(cid)
	if err != nil {
		return err
	}

	err = persist.Client.Set(persist.Context, "client:"+cid.ID, result, 0).Err()
	if err != nil {
		return err
	}

	return nil
}

func (persist *Persistence) GetClientID(id string) (*ClientID, error) {
	// unmarshal json gob bytes into struct: https://stackoverflow.com/questions/53697507/save-generic-struct-to-redis
	var cid ClientID
	result, err := persist.Client.Get(persist.Context, "client:"+id).Result()
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(result), &cid)
	if err != nil {
		return nil, err
	}

	return &cid, nil
}
package tmpauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/distribution/distribution/v3/registry/auth"
)

type configClaims struct {
	Secret   string `json:"secret"`
	clientID []byte `json:"-"`
	jwt.StandardClaims
}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	realm, ok := options["realm"].(string)
	if !ok {
		return nil, fmt.Errorf(`"realm" must be set for tmpauth access controller`)
	}

	secret, ok := options["secret"].(string)
	if !ok {
		return nil, fmt.Errorf(`"secret" must be set for tmpauth access controller`)
	}

	publicKey, ok := options["publickey"].(string)
	if !ok {
		return nil, fmt.Errorf(`"publickey" must be set for tmpauth access controller`)
	}

	pubKeyData, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("tmpauth: invalid public_key: %w", err)
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyData)
	if x == nil {
		return nil, fmt.Errorf("tmpauth: invalid public_key")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	token, err := jwt.ParseWithClaims(secret, &configClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("tmpauth: invalid secret signing method: %v", token.Header["alg"])
		}

		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("tmpauth: invalid secret: %w", err)
	}

	claims := token.Claims.(*configClaims)

	if claims.Secret == "" {
		return nil, fmt.Errorf("tmpauth: secret cannot be empty")
	}

	return &accessController{
		realm:     realm,
		clientID:  claims.Subject,
		secret:    []byte(claims.Secret),
		publicKey: pubKey,

		tokenCache:      make(map[[32]byte]*CachedToken),
		tokenCacheMutex: new(sync.RWMutex),

		httpClient: &http.Client{
			Transport: &Transport{
				token: secret,
				base:  http.DefaultTransport,
			},
			Timeout: time.Second * 10,
		},
	}, nil
}

func init() {
	auth.Register("tmpauth", auth.InitFunc(newAccessController))
}

package tmpauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/tidwall/gjson"
)

const TmpAuthHost = "auth.tmpim.pw"
const offlineUser = "offline"

func (ac *accessController) authenticateUser(username, password string) error {
	ac.janitorOnce.Do(func() {
		go ac.janitor()
	})

	if username == offlineUser && subtle.ConstantTimeCompare([]byte(password), []byte(ac.offlineKey)) == 1 {
		return nil
	}

	token, err := ac.parseWrappedAuthJWT(password)
	if err != nil {
		return err
	}

	result := gjson.Get(token.UserDescriptor, "whomst.name")
	if !result.Exists() || result.String() != username {
		return fmt.Errorf("tmpauth: username does not match")
	}

	return nil
}

type CachedToken struct {
	StateID        string
	UserDescriptor string
	Expiry         time.Time
	RevalidateAt   time.Time
	IssuedAt       time.Time
	UserIDs        []string // IDs that can be used in Config.AllowedUsers from IDFormats
	headersMutex   *sync.RWMutex
}

type wrappedToken struct {
	Token    string `json:"token"`
	clientID string `json:"-"`
	jwt.StandardClaims
}

func (w *wrappedToken) Valid() error {
	if !w.VerifyAudience(TmpAuthHost+":server:user_cookie:"+w.clientID, true) {
		return fmt.Errorf("tmpauth: audience invalid, got: %v", w.Audience)
	}

	if !w.VerifyExpiresAt(time.Now().Unix(), false) {
		return fmt.Errorf("tmpauth: token expired")
	}

	return nil
}

func (ac *accessController) parseWrappedAuthJWT(tokenStr string, doNotCache ...bool) (*CachedToken, error) {
	tokenID := sha256.Sum256([]byte(tokenStr))

	ac.tokenCacheMutex.RLock()
	cachedToken, found := ac.tokenCache[tokenID]
	ac.tokenCacheMutex.RUnlock()

	if found && cachedToken.RevalidateAt.After(time.Now()) {
		// fast path, token already verified and cached in-memory
		return cachedToken, nil
	}

	// slow path, token is verified
	wTokenRaw, err := jwt.ParseWithClaims(tokenStr, &wrappedToken{
		clientID: ac.clientID,
	}, ac.VerifyWithSecret)
	if err != nil {
		return nil, err
	}

	wToken := wTokenRaw.Claims.(*wrappedToken)

	cachedToken, err = ac.parseAuthJWT(wToken.Token)
	if err != nil {
		return nil, err
	}

	if len(doNotCache) == 0 {
		ac.tokenCacheMutex.Lock()
		ac.tokenCache[tokenID] = cachedToken
		ac.tokenCacheMutex.Unlock()
	}

	return cachedToken, nil
}

func (ac *accessController) parseAuthJWT(tokenStr string) (*CachedToken, error) {
	token, err := jwt.Parse(tokenStr, ac.VerifyWithPublicKey)
	if err != nil {
		return nil, err
	}

	mapClaims := token.Claims.(jwt.MapClaims)
	if !mapClaims.VerifyAudience(TmpAuthHost+":server:identity:"+ac.clientID, true) {
		return nil, fmt.Errorf("tmpauth: invalid audience: %v", mapClaims["aud"])
	}
	if !mapClaims.VerifyIssuer(TmpAuthHost+":central", true) {
		return nil, fmt.Errorf("tmpauth: issuer invalid, got: %v", mapClaims["iss"])
	}
	if !mapClaims.VerifyExpiresAt(time.Now().Unix(), false) {
		return nil, fmt.Errorf("tmpauth: token expired")
	}
	if !mapClaims.VerifyIssuedAt(time.Now().Unix()+300, true) {
		return nil, fmt.Errorf("tmpauth: invalid iat, got: %v", mapClaims["iat"])
	}

	resp, err := ac.httpClient.Get("https://" + TmpAuthHost + "/whomst/tmpauth?token=" + url.QueryEscape(tokenStr))
	if err != nil {
		return nil, fmt.Errorf("tmpauth: failed to retrieve whomst data: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("tmpauth: got non OK response when retrieving token: %v", resp.Status)
	}

	var whomstData interface{}
	err = json.NewDecoder(resp.Body).Decode(&whomstData)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("tmpauth: failed to read whomst response: %w", err)
	}

	var expiry time.Time
	switch exp := mapClaims["exp"].(type) {
	case float64:
		expiry = time.Unix(int64(exp), 0)
	case json.Number:
		v, _ := exp.Int64()
		expiry = time.Unix(int64(v), 0)
	default:
		expiry = time.Now().Add(3650 * 24 * time.Hour)
	}

	var iat time.Time
	switch assertedIat := mapClaims["iat"].(type) {
	case float64:
		iat = time.Unix(int64(assertedIat), 0)
	case json.Number:
		v, _ := assertedIat.Int64()
		iat = time.Unix(int64(v), 0)
	default:
		return nil, fmt.Errorf("tmpauth: iat impossibly unavailable, this is a bug: %v", mapClaims["iat"])
	}

	// remarshal to ensure that json has no unnecessary whitespace.
	descriptor, err := json.Marshal(&userDescriptor{
		Whomst: whomstData,
		Token:  token.Claims,
	})
	if err != nil {
		return nil, fmt.Errorf("tmpauth: fatal error: failed to marshal user descriptor: %w", err)
	}

	revalidateAt := time.Now().Add(15 * time.Minute)
	if revalidateAt.After(expiry) {
		revalidateAt = expiry
	}

	cachedToken := &CachedToken{
		UserDescriptor: string(descriptor),
		Expiry:         expiry,
		RevalidateAt:   revalidateAt,
		IssuedAt:       iat,
		headersMutex:   new(sync.RWMutex),
	}

	return cachedToken, nil
}

func (ac *accessController) VerifyWithPublicKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, fmt.Errorf("tmpauth: expected ECDSA signing method, got: %v", token.Header["alg"])
	}

	return ac.publicKey, nil
}

func (ac *accessController) VerifyWithSecret(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("tmpauth: expected HMAC signing method, got: %v", token.Header["alg"])
	}

	return ac.secret, nil
}

func (ac *accessController) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	for {
		select {
		case <-ticker.C:
			ac.tokenCacheMutex.Lock()

			now := time.Now()
			for k, v := range ac.tokenCache {
				if now.After(v.RevalidateAt) {
					delete(ac.tokenCache, k)
				}
			}

			ac.tokenCacheMutex.Unlock()
		}
	}
}

type userDescriptor struct {
	Whomst interface{} `json:"whomst"`
	Token  jwt.Claims  `json:"token"`
}

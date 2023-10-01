// Package tmpauth providers a tmpauth authentication scheme for the registry.
package tmpauth

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"sync"

	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/auth"
)

type accessController struct {
	realm           string
	clientID        string
	secret          []byte
	offlineKey      string
	publicKey       *ecdsa.PublicKey
	tokenCache      map[[32]byte]*CachedToken
	tokenCacheMutex *sync.RWMutex
	httpClient      *http.Client

	janitorOnce *sync.Once
}

var _ auth.AccessController = &accessController{}

func (ac *accessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := dcontext.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		return nil, &challenge{
			realm: ac.realm,
			err:   auth.ErrInvalidCredential,
		}
	}

	if err := ac.authenticateUser(username, password); err != nil {
		dcontext.GetLogger(ctx).Errorf("error authenticating user %q: %v", username, err)
		return nil, &challenge{
			realm: ac.realm,
			err:   auth.ErrAuthenticationFailure,
		}
	}

	return auth.WithUser(ctx, auth.UserInfo{Name: username}), nil
}

// challenge implements the auth.Challenge interface.
type challenge struct {
	realm string
	err   error
}

var _ auth.Challenge = challenge{}

// SetHeaders sets the basic challenge header on the response.
func (ch challenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ch.realm))
}

func (ch challenge) Error() string {
	return fmt.Sprintf("basic authentication challenge for realm %q: %s", ch.realm, ch.err)
}

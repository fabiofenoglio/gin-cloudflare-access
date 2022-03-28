package gincloudflareaccess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	resty "github.com/go-resty/resty/v2"
)

const (
	TypeApp = "app"
)

// CloudflareAccessClient is a component that verifies the provided JWT token
// against Cloudflare verification APIs.
//
// It also fetches the groups associated with the provided authentication.
type cloudflareAccessClient interface {
	VerifyToken(context.Context, string) (*oidc.IDToken, error)
	BuildPrincipal(ctx context.Context, raw string, token *oidc.IDToken) (*CloudflareAccessPrincipal, error)
}

type cloudflareAccessClientImpl struct {
	config     *cloudflareAccessClientConfig
	groupsURL  string
	oidcConfig *oidc.Config
	keySet     oidc.KeySet
	verifier   *oidc.IDTokenVerifier
}

type cloudflareAccessClientConfig struct {
	AuthTeamDomain string
	AuthPolicyAUD  []string

	// for testing purpose
	keySet          oidc.KeySet
	identityFetcher func(context.Context, string, *oidc.IDToken) (*CloudflareIdentity, error)
}

func newCloudflareAccessClient(c *cloudflareAccessClientConfig) cloudflareAccessClient {

	teamDomain := c.AuthTeamDomain

	groupsURL := fmt.Sprintf("%s/cdn-cgi/access/get-identity", teamDomain)

	oidcConfig := &oidc.Config{
		ClientID:          "",
		SkipClientIDCheck: true,
	}

	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", teamDomain)

	var keySet oidc.KeySet
	if c.keySet != nil {
		keySet = c.keySet
	} else {
		keySet = oidc.NewRemoteKeySet(context.Background(), certsURL)
	}

	return &cloudflareAccessClientImpl{
		config:    c,
		groupsURL: groupsURL,

		oidcConfig: oidcConfig,
		keySet:     keySet,
		verifier:   oidc.NewVerifier(teamDomain, keySet, oidcConfig),
	}
}

// VerifyToken verifies the given JWT token against the provided configuration parameters
// calling the cloudflare key endpoints when needed.
func (s *cloudflareAccessClientImpl) VerifyToken(ctx context.Context, raw string) (*oidc.IDToken, error) {
	// Verify the access token
	token, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}

	// manually verify the audience as multiple values are allowed
	if token.Issuer == "" {
		return nil, errors.New("empty token issuer is not allowed")
	}
	if token.Audience == nil || len(token.Audience) < 1 {
		return nil, errors.New("empty token audience is not allowed")
	}

	audienceOk := false

outer:
	for _, declaredAudience := range token.Audience {
		for _, candidate := range s.config.AuthPolicyAUD {
			if candidate == declaredAudience {
				audienceOk = true
				break outer
			}
		}
	}

	if !audienceOk {
		return nil, fmt.Errorf("invalid audience: %v", token.Audience)
	}

	return token, err
}

func (s *cloudflareAccessClientImpl) BuildPrincipal(ctx context.Context, raw string, token *oidc.IDToken) (*CloudflareAccessPrincipal, error) {
	var localClaims jwtClaims

	if err := token.Claims(&localClaims); err != nil {
		// handle error
		return nil, fmt.Errorf("error parsing jwt claim: %w", err)
	}

	cfToken := CloudflareJWT{
		RawToken: token,

		Issuer:   token.Issuer,
		Audience: token.Audience,
		Subject:  token.Subject,
		Expiry:   token.Expiry,
		IssuedAt: token.IssuedAt,

		Email:         localClaims.Email,
		IdentityNonce: localClaims.IdentityNonce,
		Country:       localClaims.Country,

		Type:       localClaims.Type,
		CommonName: localClaims.CommonName,
	}

	var identity *CloudflareIdentity

	if cfToken.IsUser() {
		fetchedIdentity, err := s.fetchIdentity(ctx, raw, token)
		if err != nil {
			return nil, fmt.Errorf("error fetching user identity: %v", err)
		}
		identity = fetchedIdentity
	}

	principal := CloudflareAccessPrincipal{
		Token:      &cfToken,
		Identity:   identity,
		Email:      localClaims.Email,
		CommonName: localClaims.CommonName,
	}

	return &principal, nil
}

// extractGroups makes an HTTP call to a specific endpoint in order to extract the list
// of groups that the user belongs to.
func (s *cloudflareAccessClientImpl) fetchIdentity(ctx context.Context, raw string, token *oidc.IDToken) (*CloudflareIdentity, error) {
	// fetching from https://<teamDomain>.cloudflareaccess.com/cdn-cgi/access/get-identity
	if s.config.identityFetcher != nil {
		return s.config.identityFetcher(ctx, raw, token)
	}

	var identityResponse CloudflareIdentity

	client := resty.New()

	client.SetCookie(&http.Cookie{
		Name:     "CF_Authorization",
		Value:    raw,
		Path:     "/",
		Domain:   s.config.AuthTeamDomain,
		MaxAge:   36000,
		HttpOnly: true,
		Secure:   false,
	})

	resp, err := client.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json").
		SetResult(&identityResponse).
		Get(s.groupsURL)

	if err != nil {
		return nil, fmt.Errorf("error executing HTTP request to retrieve user groups: %w", err)
	}

	if resp.StatusCode() >= 300 {
		return nil, fmt.Errorf("got HTTP server error reading user groups: %v %v", resp.StatusCode(), resp.Status())
	}

	return &identityResponse, nil
}

// CloudflareIdentity is the REST model for the response holding the user identity
type CloudflareIdentity struct {
	Id                 string                          `json:"id"`
	Name               string                          `json:"name"`
	Email              string                          `json:"email"`
	UserUUID           string                          `json:"user_uuid"`
	AccountId          string                          `json:"account_id"`
	IP                 string                          `json:"ip"`
	AuthStatus         string                          `json:"auth_status"`
	CommonName         string                          `json:"common_name"`
	ServiceTokenId     string                          `json:"service_token_id"`
	ServiceTokenStatus bool                            `json:"service_token_status"`
	IsWarp             bool                            `json:"is_warp"`
	IsGateway          bool                            `json:"is_gateway"`
	Version            int                             `json:"version"`
	DeviceSessions     map[string]interface{}          `json:"device_sessions"`
	IssuedAt           int                             `json:"iat"`
	Idp                *CloudflareIdentityProvider     `json:"idp"`
	Geographical       *CloudflareIdentityGeographical `json:"geo"`
	Groups             []CloudflareIdentityGroup       `json:"groups"`
}

type CloudflareIdentityProvider struct {
	Id   string `json:"id"`
	Type string `json:"type"`
}

type CloudflareIdentityGeographical struct {
	Country string `json:"country"`
}

type CloudflareIdentityGroup struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type CloudflareAccessPrincipal struct {
	Token      *CloudflareJWT      `json:"token"`
	Identity   *CloudflareIdentity `json:"identity"`
	Email      string              `json:"email"`
	CommonName string              `json:"common_name"`
}

type CloudflareJWT struct {
	RawToken      *oidc.IDToken `json:"-"`
	Issuer        string        `json:"iss"`
	Audience      []string      `json:"aud"`
	Subject       string        `json:"sub"`
	Expiry        time.Time     `json:"exp"`
	IssuedAt      time.Time     `json:"iat"`
	Email         string        `json:"email"`
	IdentityNonce string        `json:"identity_nonce"`
	Country       string        `json:"country"`
	Type          string        `json:"type"`
	CommonName    string        `json:"common_name"`
}

// JWTClaims is the model holding the claims
// that we will need to extract from the incoming JWT token.
type jwtClaims struct {
	Email         string `json:"email"`
	IdentityNonce string `json:"identity_nonce"`
	Country       string `json:"country"`
	Type          string `json:"type"`
	CommonName    string `json:"common_name"`
}

// IsApplication returns True if the principal
// of the token is a human user with a valid email.
func (t *CloudflareJWT) IsUser() bool {
	return t.Type != TypeApp && t.CommonName == "" && t.Email != ""
}

// IsApplication returns True if the principal
// of the token is an application authenticated
// via a service token or certificate.
func (t *CloudflareJWT) IsApplication() bool {
	return t.Type == TypeApp && t.CommonName != "" && t.Email == ""
}

// IsApplication returns True if the principal
// of the token is a human user with a valid email.
func (t *CloudflareAccessPrincipal) IsUser() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.IsUser()
}

// IsApplication returns True if the principal
// of the token is an application authenticated
// via a service token or certificate.
func (t *CloudflareAccessPrincipal) IsApplication() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.IsApplication()
}

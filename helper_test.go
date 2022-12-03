package gincloudflareaccess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type staticKeySet struct {
	keys jose.JSONWebKeySet
}

type mockedTokenOptions struct {
	KeyId         string
	Issuer        string
	Subject       string
	Audience      []string
	Expiry        time.Time
	NotBefore     time.Time
	IssuedAt      time.Time
	ID            string
	Email         string
	IdentityNonce string
	Country       string
}

func mockIdentityFetcher() func(context.Context, string, *oidc.IDToken) (*CloudflareIdentity, error) {
	return func(c context.Context, s string, i *oidc.IDToken) (*CloudflareIdentity, error) {
		var localClaims jwtClaims
		if err := i.Claims(&localClaims); err != nil {
			panic(err)
		}
		mockedIdentity := mockIdentity(&mockedTokenOptions{
			Email:   localClaims.Email,
			Subject: i.Subject,
		})
		return mockedIdentity, nil
	}
}

func defaultMockedTokenOptions() *mockedTokenOptions {
	now := time.Now()

	return &mockedTokenOptions{
		KeyId:   "1",
		Issuer:  "https://organization.cloudflareaccess.com",
		Subject: "1",
		Audience: []string{
			"myorganizationaudience123123123123",
		},
		ID:            "f4c393b5-1234-1234-1234-d890a24446e6",
		Email:         "user@organization.com",
		IdentityNonce: "ae8b98de-1234-1234-1234-6b11f93a7a4e",
		Country:       "IT",
		IssuedAt:      now,
		NotBefore:     now,
		Expiry:        now.Add(time.Duration(15) * time.Minute),
	}
}

func mockedGroups() []interface{} {
	ldapGroups := []map[string]interface{}{
		{
			"id":    "groupid000",
			"name":  "Group 0",
			"email": "group0@organization.com",
		},
		{
			"id":    "groupid001",
			"name":  "Group 1",
			"email": "group1@organization.com",
		},
		{
			"id":    "groupid002",
			"name":  "Group 2",
			"email": "group2@organization.com",
		}}
	result := make([]interface{}, len(ldapGroups))
	for i, d := range ldapGroups {
		result[i] = interface{}(d)
	}
	return result

}

func mockPrincipal(tokenOptions *mockedTokenOptions) *CloudflareAccessPrincipal {
	parsedtoken := mockParsedToken(tokenOptions)
	identity := mockIdentity(tokenOptions)

	return &CloudflareAccessPrincipal{
		Token:    parsedtoken,
		Identity: identity,
		Email:    identity.Email,
	}
}

func mockParsedToken(tokenOptions *mockedTokenOptions) *CloudflareJWT {

	return &CloudflareJWT{

		RawToken: &oidc.IDToken{
			Issuer:          tokenOptions.Issuer,
			Audience:        tokenOptions.Audience,
			Subject:         tokenOptions.Subject,
			Expiry:          tokenOptions.Expiry,
			IssuedAt:        tokenOptions.IssuedAt,
			Nonce:           tokenOptions.IdentityNonce,
			AccessTokenHash: "",
		},
		Issuer:        tokenOptions.Issuer,
		Audience:      tokenOptions.Audience,
		Subject:       tokenOptions.Subject,
		Expiry:        tokenOptions.Expiry,
		IssuedAt:      tokenOptions.IssuedAt,
		Email:         tokenOptions.Email,
		IdentityNonce: tokenOptions.IdentityNonce,
		Country:       tokenOptions.Country,
	}
}

func mockIdentity(tokenOptions *mockedTokenOptions) *CloudflareIdentity {
	out := CloudflareIdentity{
		Id:                 "1234567890",
		Name:               "User",
		Email:              tokenOptions.Email,
		UserUUID:           tokenOptions.Subject,
		AccountId:          "28d8ec7b-1234-1234-1234-f80fdea8383e",
		IP:                 "1.2.3.4",
		AuthStatus:         "NONE",
		CommonName:         "",
		ServiceTokenId:     "",
		ServiceTokenStatus: false,
		IsWarp:             false,
		IsGateway:          false,
		Version:            0,
		DeviceSessions:     make(map[string]interface{}),
		IssuedAt:           int(time.Now().Unix()),
		Idp: &CloudflareIdentityProvider{
			Id:   "29514573-1234-1234-1234-4912c3452248",
			Type: "google",
		},
		Geographical: &CloudflareIdentityGeographical{
			Country: "IT",
		},
		Groups: mockedGroups(),
	}

	return &out
}

func customMockSignedToken(customizer func(*mockedTokenOptions)) string {
	defOptions := defaultMockedTokenOptions()
	customizer(defOptions)
	return mockSignedToken(*defOptions)
}

func defaultMockSignedToken() string {
	return mockSignedToken(*defaultMockedTokenOptions())
}

func mockSignedToken(input mockedTokenOptions) string {
	jwk := jose.JSONWebKey{}

	bytes, err := os.ReadFile(fmt.Sprintf("./mock/jwk_private_%s.json", input.KeyId))
	if err != nil {
		panic(err)
	}

	err = jwk.UnmarshalJSON(bytes)
	if err != nil {
		panic(err)
	}

	options := jose.SigningKey{Algorithm: jose.RS256, Key: jwk}

	signer, err := jose.NewSigner(options, nil)
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{
		Audience: jwt.Audience(input.Audience),
		Subject:  input.Subject,
		Issuer:   input.Issuer,
	}

	if input.IssuedAt.Unix() > 0 {
		cl.IssuedAt = jwt.NewNumericDate(input.IssuedAt)
	}

	if input.NotBefore.Unix() > 0 {
		cl.NotBefore = jwt.NewNumericDate(input.NotBefore)
	}

	if input.Expiry.Unix() > 0 {
		cl.Expiry = jwt.NewNumericDate(input.Expiry)
	}

	customClaims := jwtClaims{
		Email:         input.Email,
		IdentityNonce: input.IdentityNonce,
		Country:       input.Country,
	}

	raw, err := jwt.Signed(signer).Claims(cl).Claims(customClaims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	return raw
}

func serveRequest(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	return w
}

func newStaticKeySet(keys jose.JSONWebKeySet) *staticKeySet {
	return &staticKeySet{keys: keys}
}

func (l *staticKeySet) verify(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {

	for _, key := range l.keys.Keys {
		_, _, payload, err := jws.VerifyMulti(key)
		if err == nil {
			return payload, nil
		}
	}

	return nil, errors.New("failed to verify id token signature")
}

// VerifySignature verifies a JWT based on a static JSONWebKeySet
func (l *staticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}

	return l.verify(ctx, jws)
}

func mockPublicKeySet() oidc.KeySet {
	keyset := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{},
	}

	jwk := jose.JSONWebKey{}
	bytes, err := os.ReadFile("./mock/jwk_public_1.json")
	if err != nil {
		panic(err)
	}
	err = jwk.UnmarshalJSON(bytes)
	if err != nil {
		panic(err)
	}
	keyset.Keys = append(keyset.Keys, jwk)

	jwk2 := jose.JSONWebKey{}
	bytes, err = os.ReadFile("./mock/jwk_public_2.json")
	if err != nil {
		panic(err)
	}
	err = jwk2.UnmarshalJSON(bytes)
	if err != nil {
		panic(err)
	}
	keyset.Keys = append(keyset.Keys, jwk2)

	return newStaticKeySet(keyset)
}

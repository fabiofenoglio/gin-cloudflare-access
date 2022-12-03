package gincloudflareaccess

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func buildTestRouter(r *gin.Engine, cfAccess CloudflareAccessMiddleware) {
	helloHandler := func(c *gin.Context) {
		principal := GetPrincipal(c)
		if principal != nil {
			c.JSON(200, "hello "+principal.Email)
		} else {
			c.JSON(200, "hello guest")
		}
	}

	// plugin the load limiter middleware for all routes like this:
	r.Use(cfAccess.AuthenticationMiddleware())

	r.GET("/", helloHandler)

	secured := r.Group("/secured", cfAccess.RequireAuthenticated())
	secured.GET("/hello", helloHandler)
	secured.GET("/whoami", func(c *gin.Context) {
		principal := GetPrincipal(c)
		c.JSON(200, principal)
	})

	group0 := r.Group("/group0", cfAccess.RequireGroup("group0@organization.com"))
	group0.GET("/hello", helloHandler)

	group01 := r.Group("/group01", cfAccess.RequireAllGroups([]string{
		"group0@organization.com",
		"group1@organization.com",
	}))
	group01.GET("/hello", helloHandler)

	groupX := r.Group("/groupX", cfAccess.RequireGroup("groupX@organization.com"))
	groupX.GET("/hello", helloHandler)

	group1X := r.Group("/group1X", cfAccess.RequireAllGroups([]string{
		"group1@organization.com",
		"groupX@organization.com",
	}))
	group1X.GET("/hello", helloHandler)

	group1Xa := r.Group("/group1Xa", cfAccess.RequireAnyGroup([]string{
		"group1@organization.com",
		"groupX@organization.com",
	}))
	group1Xa.GET("/hello", helloHandler)

	groupXYa := r.Group("/groupXYa", cfAccess.RequireAnyGroup([]string{
		"groupY@organization.com",
		"groupX@organization.com",
	}))
	groupXYa.GET("/hello", helloHandler)

	groupRequireCustom := r.Group("/require-custom", cfAccess.Require(func(c *gin.Context, principal *CloudflareAccessPrincipal) error {
		if principal == nil {
			return errors.New("auth required")
		}
		if c.Request.Header.Get("X-Mock-Allow") != principal.Email {
			return errors.New("required custom header not valid")
		}
		return nil
	}))
	groupRequireCustom.GET("/hello", helloHandler)
}

func TestGinIntegration(t *testing.T) {
	r := gin.Default()

	cfAccess := NewCloudflareAccessMiddleware(&Config{
		TeamDomain: "organization",
		ValidAudiences: []string{
			"myorganizationaudience123123123123",
		},

		keySet:          mockPublicKeySet(),
		identityFetcher: mockIdentityFetcher(),
	})

	buildTestRouter(r, cfAccess)

	// simulate requests

	// call / as guest
	req, _ := http.NewRequest("GET", "/", nil)
	w := serveRequest(r, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello guest\"", w.Body.String())

	// call /secured/whoami as guest
	req, _ = http.NewRequest("GET", "/secured/whoami", nil)
	w = serveRequest(r, req)
	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call / as default mock user
	signed := defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello user@organization.com\"", w.Body.String())

	// call / as another user
	signed = customMockSignedToken(func(tokenOptions *mockedTokenOptions) {
		tokenOptions.Email = "another-user@organization.com"
		tokenOptions.Subject = "anotheruser123123123123"
	})

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello another-user@organization.com\"", w.Body.String())

	// call /secured/whoami as default mock user
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/secured/whoami", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "user@organization.com")
	assert.Contains(t, w.Body.String(), "group0@organization.com")
	assert.Contains(t, w.Body.String(), "group1@organization.com")
	assert.Contains(t, w.Body.String(), "group2@organization.com")
	assert.NotContains(t, w.Body.String(), "groupX@organization.com")
	assert.Contains(t, w.Body.String(), "https://organization.cloudflareaccess.com")
	assert.Contains(t, w.Body.String(), "User")
	assert.Contains(t, w.Body.String(), "1.2.3.4")

	// call / as another user signed with a different key
	signed = customMockSignedToken(func(tokenOptions *mockedTokenOptions) {
		tokenOptions.KeyId = "2"
		tokenOptions.Email = "another-user@organization.com"
		tokenOptions.Subject = "anotheruser123123123123"
	})

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello another-user@organization.com\"", w.Body.String())

	// call / as another user signed with an unrecognized key
	signed = customMockSignedToken(func(tokenOptions *mockedTokenOptions) {
		tokenOptions.KeyId = "9"
		tokenOptions.Email = "another-user@organization.com"
		tokenOptions.Subject = "anotheruser123123123123"
	})

	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), "failed to verify signature")
	assert.Contains(t, w.Body.String(), "\"error\":\"Unauthorized\"")

	// call /group0/hello as default mock user
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/group0/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello user@organization.com\"", w.Body.String())

	// call /group0/hello as guest
	req, _ = http.NewRequest("GET", "/group0/hello", nil)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call /groupX/hello as default mock user
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/groupX/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"error\":\"Forbidden\",\"message\":\"forbidden\",\"status\":403}", w.Body.String())

	// call /groupX/hello as guest
	req, _ = http.NewRequest("GET", "/groupX/hello", nil)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call /group01/hello as default mock user
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/group01/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello user@organization.com\"", w.Body.String())

	// call /group1X/hello as default mock user
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/group1X/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"error\":\"Forbidden\",\"message\":\"forbidden\",\"status\":403}", w.Body.String())

	// call /group1Xa/hello as default mock user
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/group1Xa/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello user@organization.com\"", w.Body.String())

	// call /group1Xa/hello as guest
	req, _ = http.NewRequest("GET", "/group1Xa/hello", nil)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call /groupXYa/hello as guest
	req, _ = http.NewRequest("GET", "/groupXYa/hello", nil)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call /groupXYa/hello as default mock user
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/groupXYa/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"error\":\"Forbidden\",\"message\":\"forbidden\",\"status\":403}", w.Body.String())

	// call /require-custom/hello as default mock user without required header
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/require-custom/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"error\":\"Forbidden\",\"message\":\"required custom header not valid\",\"status\":403}", w.Body.String())

	// call /require-custom/hello as default mock user with required header
	signed = defaultMockSignedToken()
	req, _ = http.NewRequest("GET", "/require-custom/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	req.Header.Add("X-Mock-Allow", "user@organization.com")
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello user@organization.com\"", w.Body.String())
}

func TestDefaultTokenExtraction(t *testing.T) {
	r := gin.Default()

	cfAccess := NewCloudflareAccessMiddleware(&Config{
		TeamDomain: "organization",
		ValidAudiences: []string{
			"myorganizationaudience123123123123",
		},

		keySet:          mockPublicKeySet(),
		identityFetcher: mockIdentityFetcher(),
	})

	buildTestRouter(r, cfAccess)

	// simulate requests
	signed := defaultMockSignedToken()

	// call / as guest
	req, _ := http.NewRequest("GET", "/", nil)
	w := serveRequest(r, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello guest\"", w.Body.String())

	// call / as default mock user
	req, _ = http.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  defaultCookieName,
		Value: signed,
	})

	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello user@organization.com\"", w.Body.String())
}

func TestTokenExtractor(t *testing.T) {
	r := gin.Default()

	cfAccess := NewCloudflareAccessMiddleware(&Config{
		TeamDomain: "organization",
		ValidAudiences: []string{
			"myorganizationaudience123123123123",
		},

		keySet:          mockPublicKeySet(),
		identityFetcher: mockIdentityFetcher(),

		TokenExtractFunc: func(c *gin.Context) (string, error) {
			return c.Request.Header.Get("X-Custom-Auth"), nil
		},
	})

	buildTestRouter(r, cfAccess)

	// simulate requests
	signed := defaultMockSignedToken()

	// call / as guest
	req, _ := http.NewRequest("GET", "/", nil)
	w := serveRequest(r, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello guest\"", w.Body.String())

	// call / as default mock user
	// should NOT work with default header name now
	req, _ = http.NewRequest("GET", "/", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello guest\"", w.Body.String())

	// call /group0/hello as guest
	req, _ = http.NewRequest("GET", "/group0/hello", nil)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call /group0/hello as default mock user
	// should NOT work with default header name now
	req, _ = http.NewRequest("GET", "/group0/hello", nil)
	req.Header.Add(defaultHeaderName, signed)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call /group0/hello as default mock user
	// should accept the custom header
	req, _ = http.NewRequest("GET", "/group0/hello", nil)
	req.Header.Add("X-Custom-Auth", signed)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello user@organization.com\"", w.Body.String())
}

func TestCustomAuthenticationFunc(t *testing.T) {
	r := gin.Default()
	groups := make([]interface{}, 1)
	groups[0] = map[string]interface{}{
		"id":    "group0",
		"name":  "Some Group",
		"email": "somegroup@mock.com",
	}
	cfAccess := NewCloudflareAccessMiddleware(&Config{
		TeamDomain: "organization",
		ValidAudiences: []string{
			"myorganizationaudience123123123123",
		},

		keySet:          mockPublicKeySet(),
		identityFetcher: mockIdentityFetcher(),

		TokenExtractFunc: func(c *gin.Context) (string, error) {
			return c.Request.Header.Get("X-Mocked-Auth"), nil
		},

		AuthenticationFunc: func(ctx context.Context, s string) (*CloudflareAccessPrincipal, error) {
			return &CloudflareAccessPrincipal{
				Identity: &CloudflareIdentity{
					Email:  s + "@mock.com",
					Name:   "some mocked user",
					Groups: groups,
				},
				Email:      s + "@mock.com",
				CommonName: "user " + s,
			}, nil
		},
	})

	buildTestRouter(r, cfAccess)

	headerValue := "000"

	// call / as guest
	req, _ := http.NewRequest("GET", "/", nil)
	w := serveRequest(r, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello guest\"", w.Body.String())

	// call /group0/hello as guest
	req, _ = http.NewRequest("GET", "/group0/hello", nil)
	w = serveRequest(r, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"error\":\"Unauthorized\",\"message\":\"authentication required\",\"status\":401}", w.Body.String())

	// call /secured/hello as default mock user
	req, _ = http.NewRequest("GET", "/secured/hello", nil)
	req.Header.Add("X-Mocked-Auth", headerValue)
	w = serveRequest(r, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "\"hello 000@mock.com\"", w.Body.String())

	// call /group0/hello as default mock user
	req, _ = http.NewRequest("GET", "/group0/hello", nil)
	req.Header.Add("X-Mocked-Auth", headerValue)
	w = serveRequest(r, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"error\":\"Forbidden\",\"message\":\"forbidden\",\"status\":403}", w.Body.String())
}

package gincloudflareaccess

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

const (
	cloudflareAccessContextKeyPrincipal = "CFAccessPrincipal"
	cloudflareAccessContextKeyMarker    = "CFAccessMarker"

	defaultHeaderName = "Cf-Access-Jwt-Assertion"
	defaultCookieName = "CF_Authorization"
)

func (instance *cloudflareAccessMiddlewareImpl) AuthenticationMiddleware() gin.HandlerFunc {
	return buildAuthenticatorMiddleware(instance)
}

func (instance *cloudflareAccessMiddlewareImpl) extractToken(c *gin.Context) (string, error) {
	if instance.config.TokenExtractFunc != nil {
		return instance.config.TokenExtractFunc(c)
	}

	// look first in the headers
	headers := c.Request.Header
	accessJWT := headers.Get(defaultHeaderName)

	// look for a value in the cookies
	if accessJWT == "" {
		cookieValue, cookieErr := c.Request.Cookie(defaultCookieName)
		if cookieErr == nil && cookieValue != nil && cookieValue.Value != "" {
			accessJWT = cookieValue.Value
		}
	} else {
		accessJWT = strings.TrimPrefix(accessJWT, "Bearer ")
	}

	return accessJWT, nil
}

func buildAuthenticatorMiddleware(instance *cloudflareAccessMiddlewareImpl) gin.HandlerFunc {
	var tokenCache *cache.Cache
	if !instance.config.DisableCache {
		effectiveDuration := instance.config.CacheTTL
		if effectiveDuration == 0 {
			effectiveDuration = 5 * time.Minute
		}

		tokenCache = cache.New(effectiveDuration, 5*time.Minute)
	}

	return func(c *gin.Context) {
		// Mark the request as processed from the engine
		c.Set(cloudflareAccessContextKeyMarker, 1)

		// Make sure that the incoming request has our token header.
		accessJWT, err := instance.extractToken(c)
		if err != nil {
			instance.handleUnauthorized(c, fmt.Errorf("error extracting token: %v", err))
			return
		}

		if accessJWT == "" {
			// There's no authorization token source.
			// We go on and don't error right now as this may be a call to a public resource.
			c.Next()
			return
		}

		if !instance.config.DisableCache {
			// Check if the token is cached
			if cachedPrincipalRaw, found := tokenCache.Get(accessJWT); found {
				cachedPrincipal := cachedPrincipalRaw.(*CloudflareAccessPrincipal)

				// Set the principal in the call context and proceed
				c.Set(cloudflareAccessContextKeyPrincipal, cachedPrincipal)
				c.Next()
				return
			}
		}

		var token *oidc.IDToken
		var principal *CloudflareAccessPrincipal

		if instance.config.AuthenticationFunc != nil {

			principal, err = instance.config.AuthenticationFunc(c.Request.Context(), accessJWT)

		} else {
			// Verify the access token
			token, err = instance.cloudflareAccessClient.VerifyToken(c.Request.Context(), accessJWT)
			if err != nil {
				// Token verification failed. We block the call right now.
				instance.handleUnauthorized(c, err)
				return
			}

			// Build the principal from token
			principal, err = instance.cloudflareAccessClient.BuildPrincipal(c.Request.Context(), accessJWT, token)
		}
		if err != nil {
			// Principal identification failed. We block the call and return the error right now.
			instance.handleUnauthorized(c, fmt.Errorf("error building principal from token: %v", err))
			return
		}

		// If a custom details fetcher is provided, invoke it
		if principal != nil && instance.config.DetailsFetcher != nil {
			fetchedDetails, err := instance.config.DetailsFetcher(c, principal)
			if err != nil {
				instance.handleUnauthorized(c, fmt.Errorf("error loading user details: %v", err))
				return
			}
			principal.Details = fetchedDetails
		}

		// Set the principal in the call context and proceed
		c.Set(cloudflareAccessContextKeyPrincipal, principal)

		if !instance.config.DisableCache {
			// Put the principal in cache
			tokenCache.Set(accessJWT, principal, cache.DefaultExpiration)
		}

		// May now proceed
		c.Next()
	}
}

// GetPrincipal extracts the current principal from the request context.
//
// Note that the principal can be nil if no authentication was provided.
func GetPrincipal(c *gin.Context) *CloudflareAccessPrincipal {
	raw, exists := c.Get(cloudflareAccessContextKeyPrincipal)
	if !exists {
		return nil
	}

	converted, ok := raw.(*CloudflareAccessPrincipal)
	if !ok {
		panic(fmt.Errorf("unexpected type for principal in context: %T", raw))
	}

	return converted
}

func assertRequestProcessedByAuthenticator(c *gin.Context) {
	_, present := c.Get(cloudflareAccessContextKeyMarker)
	if !present {
		msg := "an authentication/authorization check was requested but " +
			"the current request has not been processed by the Authentication middleware. " +
			"Please ensure that you plugged the authentication middleware in the router, usually done " +
			"by calling r.Use(yourInstance.AuthenticationMiddleware()), " +
			"before plugging other middlewares such as RequireAuthenticated or RequireGroup " +
			"or before calling helpers such as GetPrincipal, PrincipalInGroups"

		log.Default().Printf("[ERROR] " + msg)
		panic(errors.New(msg))
	}
}

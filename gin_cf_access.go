package gincloudflareaccess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
)

// Config holds the basic configuration options for the CloudflareAccess integration.
//
// at least a valid TeamDomain and a ValidAudiences are required.
type Config struct {

	// TeamDomain is the name of your team.
	//
	// it's the third-level domain of your authentication portal,
	// for instance if your login page is https://organization.cloudflareaccess.com
	// then your TeamDomain is "organization"
	TeamDomain string

	// Every Access Policy created under the Access or Team portal
	// will come with a specific Audience Tag.
	//
	// You should provide at least one audience tag,
	// but you can support as many policies as you want by providing
	// multiple audience tags.
	ValidAudiences []string

	// If for some reason you want to provide the Access header
	// under a different header or with a different mechanism,
	// you can provide the TokenExtractFunc parameter.
	//
	// The function should look for an authorization token wherever you need
	// in the request, and return it.
	// If no token was found you should return an empty string and a nil error.
	// The request will be aborted if the function returns a non-nil error.
	TokenExtractFunc func(c *gin.Context) (string, error)

	// By default, principals authenticated from a token are cached in memory
	// for a short duration.
	// You can disable the caching mechanism by providing the DisableCache parameter.
	DisableCache bool

	// By default, principals authenticated from a token are cached in memory
	// for 5 minutes.
	// You can change this duration with the CacheTTL parameter.
	CacheTTL time.Duration

	// Whenever a request is blocked because of invalid or missing authentication,
	// LDAP group conditions not met or custom checks failing,
	// a default error response will be returned in JSON.
	//
	// You can change the way these errors are handled by providing a ErrorResponseHandler.
	// it should call a finalization method such as AbortWithStatusJSON.
	//
	// The ErrorResponseHandler function will be invoked with the request context,
	// the status error (either 401 or 403) and a non-nil error.
	ErrorResponseHandler func(c *gin.Context, status int, err error)

	// You can provide a function to load additional details from the principal.
	//
	// The loaded data will be attached as "Detail" field for the principal and
	// kept in cache.
	DetailsFetcher func(c *gin.Context, principal *CloudflareAccessPrincipal) (interface{}, error)

	// for testing purpose
	keySet          oidc.KeySet
	identityFetcher func(context.Context, string, *oidc.IDToken) (*CloudflareIdentity, error)
}

// CloudflareAccessMiddleware is a middleware builder
// providing middlewares for authentication,
// authorization and principals management.
type CloudflareAccessMiddleware interface {

	// AuthenticationMiddleware will build a middleware
	// that reads the authorization header or cookies
	// and, if provided, will validate and authenticate the user.
	//
	// invalid credentials and expired tokens will cause an immediate abort.
	//
	// note that, by itself, this middleware does not prevent
	// unauthenticated access nor perform any check on the authentication result
	// other than blocking invalid credentials.
	// Additional check have to be enabled with the .Require...() middlewares
	//
	// note that as every middleware, AuthenticationMiddleware() can be applied to a single route,
	// to a route group or to the whole router.
	// However, you should plug it in at the router level
	// with something like r.Use(cfAccess.AuthenticationMiddleware())
	AuthenticationMiddleware() gin.HandlerFunc

	// RequireAuthenticated will build a middleware restricting access
	// to authenticated users.
	//
	// note that as every middleware, RequireAuthenticated() can be applied to a single route,
	// to a route group or to the whole router
	RequireAuthenticated() gin.HandlerFunc

	// RequireGroup will build a middleware restricting access
	// to users belonging to a specific LDAP group
	//
	// note that as every middleware, RequireGroup() can be applied to a single route,
	// to a route group or to the whole router
	RequireGroup(group string) gin.HandlerFunc

	// RequireAnyGroup will build a middleware restricting access
	// to users belonging to at least one of some LDAP groups
	//
	// note that as every middleware, RequireAnyGroup() can be applied to a single route,
	// to a route group or to the whole router
	RequireAnyGroup(groups []string) gin.HandlerFunc

	// RequireAllGroups will build a middleware restricting access
	// to users belonging to every one of the specified LDAP groups
	//
	// note that as every middleware, RequireAllGroups() can be applied to a single route,
	// to a route group or to the whole router
	RequireAllGroups(groups []string) gin.HandlerFunc

	// Require will build a middleware restricting access
	// by evaluating a specific custom for every request.
	//
	// the .Require() middleware can be used to implement custom checks:
	// it receives the request context and the authenticated principals
	// and it can return a non-nil error to abort the request.
	//
	// when the provided function returns an error,
	// the default behavior for forbidden requests executes, so
	// if a ErrorResponseHandler has been provided it will be
	// invoked with the returned error and a 403 status code.
	//
	// note that as every middleware, .Require() can be applied to a single route,
	// to a route group or to the whole router
	Require(check func(c *gin.Context, principal *CloudflareAccessPrincipal) error) gin.HandlerFunc
}

type cloudflareAccessMiddlewareImpl struct {
	config                 *Config
	cloudflareAccessClient cloudflareAccessClient
}

// NewCloudflareAccessMiddleware builds a CloudflareAccessMiddleware with the provided configuration.
func NewCloudflareAccessMiddleware(config *Config) CloudflareAccessMiddleware {
	err := validateConfig(config)
	if err != nil {
		panic(err)
	}

	effectiveTeamDomain := config.TeamDomain
	if !strings.HasSuffix(effectiveTeamDomain, ".cloudflareaccess.com") {
		effectiveTeamDomain = fmt.Sprintf("https://%s.cloudflareaccess.com", effectiveTeamDomain)
	}

	cfClient := newCloudflareAccessClient(&cloudflareAccessClientConfig{
		AuthTeamDomain: effectiveTeamDomain,
		AuthPolicyAUD:  config.ValidAudiences,

		keySet:          config.keySet,
		identityFetcher: config.identityFetcher,
	})

	instance := cloudflareAccessMiddlewareImpl{
		config:                 config,
		cloudflareAccessClient: cfClient,
	}

	return &instance
}

func validateConfig(config *Config) error {
	if config == nil {
		return errors.New("nil config not allowed")
	}
	if config.TeamDomain == "" {
		return errors.New("TeamDomain is required")
	}
	if config.ValidAudiences == nil || len(config.ValidAudiences) < 1 {
		return errors.New("ValidAudiences is required")
	}
	if config.CacheTTL < 0 {
		return errors.New("CacheTTL must be zero or positive duration")
	}
	return nil
}

func (instance *cloudflareAccessMiddlewareImpl) handleUnauthorized(c *gin.Context, err error) {
	if instance.config.ErrorResponseHandler != nil {
		// run the user error handler if any.
		instance.config.ErrorResponseHandler(c, http.StatusUnauthorized, err)
		if !c.IsAborted() {
			c.Abort()
		}
	} else {
		// if no custom handler is present, return 401
		errPayload := make(map[string]interface{})
		errPayload["status"] = http.StatusUnauthorized
		errPayload["error"] = "Unauthorized"
		errPayload["message"] = err.Error()
		c.AbortWithStatusJSON(http.StatusUnauthorized, errPayload)
	}
}

func (instance *cloudflareAccessMiddlewareImpl) handleForbidden(c *gin.Context, err error) {
	if instance.config.ErrorResponseHandler != nil {
		// run the user error handler if any.
		instance.config.ErrorResponseHandler(c, http.StatusForbidden, err)
		if !c.IsAborted() {
			c.Abort()
		}
	} else {
		// if no custom handler is present, return 403
		errPayload := make(map[string]interface{})
		errPayload["status"] = http.StatusForbidden
		errPayload["error"] = "Forbidden"
		errPayload["message"] = err.Error()
		c.AbortWithStatusJSON(http.StatusForbidden, errPayload)
	}
}

package gincloudflareaccess

import (
	"github.com/gin-gonic/gin"
)

// Require will build a middleware restricting access
// by evaluating a specific custom for every request.
//
// the .Require() middleware can be used to implements custom checks:
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
func (instance *cloudflareAccessMiddlewareImpl) Require(check func(c *gin.Context, principal *CloudflareAccessPrincipal) error) gin.HandlerFunc {
	return buildRequireMiddleware(instance, check)
}

func buildRequireMiddleware(instance *cloudflareAccessMiddlewareImpl, check func(c *gin.Context, principal *CloudflareAccessPrincipal) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		assertRequestProcessedByAuthenticator(c)

		if check == nil {
			c.Next()
			return
		}

		principal := GetPrincipal(c)

		err := check(c, principal)
		if err != nil {
			instance.handleForbidden(c, err)
			return
		}

		// May now proceed
		c.Next()
	}
}

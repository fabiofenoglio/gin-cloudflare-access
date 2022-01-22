package gincloudflareaccess

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// RequireAuthenticated will build a middleware restricting access
// to authenticated users.
//
// note that as every middleware, .RequireAuthenticated() can be applied to a single route,
// to a route group or to the whole router
func (instance *cloudflareAccessMiddlewareImpl) RequireAuthenticated() gin.HandlerFunc {
	return buildRequireAuthenticatedMiddleware(instance)
}

func buildRequireAuthenticatedMiddleware(instance *cloudflareAccessMiddlewareImpl) gin.HandlerFunc {
	return func(c *gin.Context) {
		assertRequestProcessedByAuthenticator(c)

		principal := GetPrincipal(c)
		if principal == nil {
			instance.handleUnauthorized(c, errors.New("authentication required"))
			return
		}

		// May now proceed
		c.Next()
	}
}

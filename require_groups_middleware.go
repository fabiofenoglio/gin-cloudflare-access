package gincloudflareaccess

import (
	"errors"

	"github.com/gin-gonic/gin"
)

type groupsRequirements struct {
	allGroups []string
	anyGroups []string
}

// RequireGroup will build a middleware restricting access
// to users belonging to a specific LDAP group
//
// note that as every middleware, .RequireGroup() can be applied to a single route,
// to a route group or to the whole router
func (instance *cloudflareAccessMiddlewareImpl) RequireGroup(group string) gin.HandlerFunc {
	return buildGroupCheckMiddleware(instance, &groupsRequirements{
		allGroups: []string{group},
	})
}

// RequireAnyGroup will build a middleware restricting access
// to users belonging to at least one of some LDAP groups
//
// note that as every middleware, .RequireAnyGroup() can be applied to a single route,
// to a route group or to the whole router
func (instance *cloudflareAccessMiddlewareImpl) RequireAnyGroup(groups []string) gin.HandlerFunc {
	return buildGroupCheckMiddleware(instance, &groupsRequirements{
		anyGroups: groups,
	})
}

// RequireAllGroups will build a middleware restricting access
// to users belonging to every one of the specified LDAP groups
//
// note that as every middleware, .RequireAllGroups() can be applied to a single route,
// to a route group or to the whole router
func (instance *cloudflareAccessMiddlewareImpl) RequireAllGroups(groups []string) gin.HandlerFunc {
	return buildGroupCheckMiddleware(instance, &groupsRequirements{
		allGroups: groups,
	})
}

func buildGroupCheckMiddleware(instance *cloudflareAccessMiddlewareImpl, requirements *groupsRequirements) gin.HandlerFunc {
	return func(c *gin.Context) {
		assertRequestProcessedByAuthenticator(c)

		if requirements == nil || ((requirements.allGroups == nil || len(requirements.allGroups) < 1) && (requirements.anyGroups == nil || len(requirements.anyGroups) < 1)) {
			c.Next()
			return
		}

		principal := GetPrincipal(c)
		if principal == nil {
			instance.handleUnauthorized(c, errors.New("authentication required"))
			return
		}

		if requirements.allGroups != nil && len(requirements.allGroups) > 0 {
			if !principalInAllGroups(principal, requirements.allGroups) {
				instance.handleForbidden(c, errors.New("forbidden"))
				return
			}
		}

		if requirements.anyGroups != nil && len(requirements.anyGroups) > 0 {
			if !principalInAnyGroups(principal, requirements.anyGroups) {
				instance.handleForbidden(c, errors.New("forbidden"))
				return
			}
		}

		// May now proceed
		c.Next()
	}
}

package gincloudflareaccess

import "github.com/gin-gonic/gin"

// Check if the user authenticated for the current request
// belongs to a specific LDAP group
func PrincipalInGroup(c *gin.Context, group string) bool {
	assertRequestProcessedByAuthenticator(c)

	if len(group) < 1 {
		return true
	}

	principal := GetPrincipal(c)
	if principal == nil || principal.Identity == nil || principal.Identity.Groups == nil || len(principal.Identity.Groups) < 1 {
		return false
	}

	for _, candidate := range principal.Identity.Groups {
		if groupMatches(&candidate, group) {
			return true
		}
	}

	return false
}

// Check if the user authenticated for the current request
// belongs to every one of the specified LDAP groups
func PrincipalInAllGroups(c *gin.Context, groups []string) bool {
	assertRequestProcessedByAuthenticator(c)

	if len(groups) < 1 {
		return true
	}

	principal := GetPrincipal(c)
	return principalInAllGroups(principal, groups)
}

// Check if the user authenticated for the current request
// belongs to at least one of some LDAP groups
func PrincipalInAnyGroups(c *gin.Context, groups []string) bool {
	assertRequestProcessedByAuthenticator(c)

	if len(groups) < 1 {
		return true
	}

	principal := GetPrincipal(c)
	return principalInAnyGroups(principal, groups)
}

func principalInAllGroups(principal *CloudflareAccessPrincipal, groups []string) bool {
	if len(groups) < 1 {
		return true
	}

	if principal == nil || principal.Identity == nil || principal.Identity.Groups == nil || len(principal.Identity.Groups) < 1 {
		return false
	}

	allFound := true
	for _, groupToFind := range groups {
		thisFound := false
		for _, candidate := range principal.Identity.Groups {
			if groupMatches(&candidate, groupToFind) {
				thisFound = true
				break
			}
		}
		if !thisFound {
			allFound = false
			break
		}
	}

	return allFound
}

func principalInAnyGroups(principal *CloudflareAccessPrincipal, groups []string) bool {
	if len(groups) < 1 {
		return true
	}

	if principal == nil || principal.Identity == nil || principal.Identity.Groups == nil || len(principal.Identity.Groups) < 1 {
		return false
	}

	for _, groupToFind := range groups {
		for _, candidate := range principal.Identity.Groups {
			if groupMatches(&candidate, groupToFind) {
				return true
			}
		}
	}

	return false
}

func groupMatches(group *CloudflareIdentityGroup, query string) bool {
	return group.Email == query || group.Id == query
}

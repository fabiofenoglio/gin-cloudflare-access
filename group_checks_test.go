package gincloudflareaccess

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func buildDefaultMockedGinContextWithPrincipal(t *testing.T) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	mockedPrincipal := mockPrincipal(defaultMockedTokenOptions())
	assert.Nil(t, GetPrincipal(c))
	c.Set(cloudflareAccessContextKeyPrincipal, mockedPrincipal)
	c.Set(cloudflareAccessContextKeyMarker, 1)
	assert.NotNil(t, GetPrincipal(c))

	return c
}

func TestPrincipalInGroup(t *testing.T) {
	c := buildDefaultMockedGinContextWithPrincipal(t)

	assert.True(t, PrincipalInGroup(c, ""))

	assert.True(t, PrincipalInGroup(c, "group0@organization.com"))
	assert.True(t, PrincipalInGroup(c, "group1@organization.com"))
	assert.True(t, PrincipalInGroup(c, "group2@organization.com"))

	assert.True(t, PrincipalInGroup(c, "groupid000"))
	assert.True(t, PrincipalInGroup(c, "groupid001"))
	assert.True(t, PrincipalInGroup(c, "groupid002"))

	assert.False(t, PrincipalInGroup(c, "groupX@organization.com"))
	assert.False(t, PrincipalInGroup(c, "groupid00X"))

	assert.False(t, PrincipalInGroup(c, "Group 0"))
	assert.False(t, PrincipalInGroup(c, "Group 1"))
	assert.False(t, PrincipalInGroup(c, "Group 2"))
}

func TestPrincipalInAllGroups(t *testing.T) {
	c := buildDefaultMockedGinContextWithPrincipal(t)

	assert.True(t, PrincipalInAllGroups(c, []string{}))
	assert.True(t, PrincipalInAllGroups(c, nil))

	assert.True(t, PrincipalInAllGroups(c, []string{
		"group0@organization.com",
	}))
	assert.True(t, PrincipalInAllGroups(c, []string{
		"group1@organization.com",
	}))
	assert.True(t, PrincipalInAllGroups(c, []string{
		"group0@organization.com",
		"group1@organization.com",
	}))
	assert.True(t, PrincipalInAllGroups(c, []string{
		"group1@organization.com",
		"group2@organization.com",
	}))
	assert.True(t, PrincipalInAllGroups(c, []string{
		"groupid000",
	}))
	assert.True(t, PrincipalInAllGroups(c, []string{
		"groupid001",
		"groupid002",
	}))
	assert.True(t, PrincipalInAllGroups(c, []string{
		"group1@organization.com",
		"group2@organization.com",
		"groupid002",
	}))

	assert.False(t, PrincipalInAllGroups(c, []string{
		"groupX@organization.com",
	}))
	assert.False(t, PrincipalInAllGroups(c, []string{
		"group1@organization.com",
		"groupX@organization.com",
	}))
	assert.False(t, PrincipalInAllGroups(c, []string{
		"group0@organization.com",
		"groupX@organization.com",
	}))
	assert.False(t, PrincipalInAllGroups(c, []string{
		"group1@organization.com",
		"group2@organization.com",
		"groupid00X",
	}))
	assert.False(t, PrincipalInAllGroups(c, []string{
		"groupid000",
		"groupid00X",
	}))
	assert.False(t, PrincipalInAllGroups(c, []string{
		"groupid00X",
		"groupid001",
		"groupid002",
	}))
	assert.False(t, PrincipalInAllGroups(c, []string{
		"group1@organization.com",
		"groupid00X",
		"group2@organization.com",
		"groupid002",
	}))
	assert.False(t, PrincipalInAllGroups(c, []string{
		"groupid00X",
		"groupX@organization.com",
	}))
}

func TestPrincipalInAnyGroups(t *testing.T) {
	c := buildDefaultMockedGinContextWithPrincipal(t)

	assert.True(t, PrincipalInAnyGroups(c, []string{}))
	assert.True(t, PrincipalInAnyGroups(c, nil))

	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group0@organization.com",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group1@organization.com",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group0@organization.com",
		"group1@organization.com",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group1@organization.com",
		"group2@organization.com",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"groupid000",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"groupid001",
		"groupid002",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group1@organization.com",
		"group2@organization.com",
		"groupid002",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group1@organization.com",
		"groupX@organization.com",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group0@organization.com",
		"groupX@organization.com",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group1@organization.com",
		"group2@organization.com",
		"groupid00X",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"groupid000",
		"groupid00X",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"groupid00X",
		"groupid001",
		"groupid002",
	}))
	assert.True(t, PrincipalInAnyGroups(c, []string{
		"group1@organization.com",
		"groupid00X",
		"group2@organization.com",
		"groupid002",
	}))

	assert.False(t, PrincipalInAnyGroups(c, []string{
		"groupX@organization.com",
	}))
	assert.False(t, PrincipalInAnyGroups(c, []string{
		"groupX@organization.com",
		"groupid00X",
	}))
	assert.False(t, PrincipalInAnyGroups(c, []string{
		"groupid00X",
		"groupid00X",
		"groupid00X",
	}))
	assert.False(t, PrincipalInAnyGroups(c, []string{
		"groupX@organization.com",
		"groupid00X",
		"groupX@organization.com",
		"groupid00X",
	}))
}

package gincloudflareaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildError(t *testing.T) {

	assert.Panics(t, func() {
		NewCloudflareAccessMiddleware(nil)
	})

	assert.Panics(t, func() {
		NewCloudflareAccessMiddleware(&Config{
			// missing required TeamDomain
			ValidAudiences: []string{
				"myorganizationaudience123123123123",
			},
		})
	})

	assert.Panics(t, func() {
		NewCloudflareAccessMiddleware(&Config{
			// missing required ValidAudiences
			TeamDomain: "myteam",
		})
	})

	assert.Panics(t, func() {
		NewCloudflareAccessMiddleware(&Config{
			TeamDomain:     "myteam",
			ValidAudiences: []string{},
			// empty required ValidAudiences
		})
	})

	assert.Panics(t, func() {
		NewCloudflareAccessMiddleware(&Config{
			TeamDomain: "myteam",
			ValidAudiences: []string{
				"myorganizationaudience123123123123",
			},
			CacheTTL: -15, // nope
		})
	})

}

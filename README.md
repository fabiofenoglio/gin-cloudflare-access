# gin-cloudflare-access

[![Documentation](https://godoc.org/github.com/fabiofenoglio/gin-cloudflare-access?status.svg)](http://godoc.org/github.com/fabiofenoglio/gin-cloudflare-access)
[![Go Report Card](https://goreportcard.com/badge/github.com/fabiofenoglio/gin-cloudflare-access)](https://goreportcard.com/report/github.com/fabiofenoglio/gin-cloudflare-access)
[![CircleCI](https://circleci.com/gh/fabiofenoglio/gin-cloudflare-access/tree/main.svg?style=shield)](https://circleci.com/gh/fabiofenoglio/gin-cloudflare-access/tree/main)
[![Coverage Status](https://coveralls.io/repos/github/fabiofenoglio/gin-cloudflare-access/badge.svg?branch=main)](https://coveralls.io/github/fabiofenoglio/gin-cloudflare-access?branch=main)

A middleware plugin for securing a Gin application behind [Cloudflare Access](https://www.cloudflare.com/teams/access/) authentication.

- [gin-cloudflare-access](#gin-cloudflare-access)
	- [Installation](#installation)
	- [Quickstart](#quickstart)
	- [Configure routes](#configure-routes)
		- [Require authentication for a route or a group of routes](#require-authentication-for-a-route-or-a-group-of-routes)
		- [Require membership to one or more LDAP groups for one or more routes](#require-membership-to-one-or-more-ldap-groups-for-one-or-more-routes)
		- [Require a custom check for a route or a group of routes](#require-a-custom-check-for-a-route-or-a-group-of-routes)
	- [Manual helpers](#manual-helpers)
		- [Retrieve the authenticated principal](#retrieve-the-authenticated-principal)
		- [Manually check if authenticated user belong to LDAP groups](#manually-check-if-authenticated-user-belong-to-ldap-groups)
	- [Customize middleware behavior](#customize-middleware-behavior)
		- [Customize error response](#customize-error-response)
		- [Customize token lookup](#customize-token-lookup)
		- [Customize caching](#customize-caching)
	- [Full example](#full-example)
	- [Available data for authenticated principals](#available-data-for-authenticated-principals)

## Installation

```
go get github.com/fabiofenoglio/gin-cloudflare-access
```

## Quickstart

```go
package main

import (
	"net/http"

	gincloudflareaccess "github.com/fabiofenoglio/gin-cloudflare-access"
	"github.com/gin-gonic/gin"
)

func main() {

	cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
		TeamDomain: "myorganization",
		ValidAudiences: []string{
			"123123123123123123123123123123123123123",
		},
	})

	r := gin.Default()

	// plug in authenticator at the root level
	r.Use(cfAccess.AuthenticationMiddleware())

	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	// require authenticated users for all routes under /secured
	authorized := r.Group("/secured", cfAccess.RequireAuthenticated())

	authorized.GET("/hello", func(c *gin.Context) {
		principal := gincloudflareaccess.GetPrincipal(c)

		c.JSON(http.StatusOK, "hello "+principal.Identity.Name)
	})

	// run the server and listen on http://localhost:9000
	err := r.Run(":9000")
	if err != nil {
		panic(err)
	}
}
```

## Configure routes

### Require authentication for a route or a group of routes

```go
cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
	// ...
})

r := gin.Default()

// plug in authenticator at the root level
r.Use(cfAccess.AuthenticationMiddleware())

// this route will NOT require authentication.
r.GET("/ping", func(c *gin.Context) {
	c.String(http.StatusOK, "pong")
})

// this route WILL require authentication
r.GET("/whoami", cfAccess.RequireAuthenticated(), func(c *gin.Context) {
	c.String(http.StatusOK, "you are a valid user")
})

// ALL routes under /secured/** will require authentication
authorized := r.Group("/secured", cfAccess.RequireAuthenticated())

authorized.GET("/hello", func(c *gin.Context) {
	principal := gincloudflareaccess.GetPrincipal(c)

	c.JSON(http.StatusOK, "hello "+principal.Identity.Name)
})

// ...
```

### Require membership to one or more LDAP groups for one or more routes

```go
cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
	// ...
})

r := gin.Default()

// plug in authenticator at the root level
r.Use(cfAccess.AuthenticationMiddleware())

// ALL routes under /only-administrators/** will be restricted
// to members of administrators@organization.com
//
// You can also use .RequireAllGroups(...) or .RequireAnyGroup(...)
authorized := r.Group("/only-administrators", cfAccess.RequireGroup("administrators@organization.com"))

authorized.GET("/hello", func(c *gin.Context) {
	// ...
})

// ...
```

### Require a custom check for a route or a group of routes

```go
cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
	// ...
})

r := gin.Default()

// plug in authenticator at the root level
r.Use(cfAccess.AuthenticationMiddleware())

// ALL routes under /only-fabio/** will be protected by this custom check
authorized := r.Group("/only-fabio", cfAccess.Require(func(c *gin.Context, principal *gincloudflareaccess.CloudflareAccessPrincipal) error {
	if principal == nil || principal.Identity.Name != "Fabio" {
		return errors.New("you are not my true father!")
	}
	return nil
}))

authorized.GET("/hello", func(c *gin.Context) {
	// ...
})

// ...
```

## Manual helpers

### Retrieve the authenticated principal

```go
r.GET("/hello", func(c *gin.Context) {
	principal := gincloudflareaccess.GetPrincipal(c)

	c.JSON(http.StatusOK, "hello "+principal.Identity.Name)
})
```

### Manually check if authenticated user belong to LDAP groups

```go
r.GET("/hello", func(c *gin.Context) {
	
	inGroup := gincloudflareaccess.PrincipalInGroup(c, "somegroup@organization.com")
	
	inAllGroups := gincloudflareaccess.PrincipalInAllGroups(c, []string{
		"group1@organization.com",
		"group2@organization.com",
		"groupid00X",
	})

	inAnyGroup := gincloudflareaccess.PrincipalInAnyGroups(c, []string{
		"group0@organization.com",
		"group1@organization.com",
	})

	// ...
})
```


## Customize middleware behavior

### Customize error response

```go
cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
	TeamDomain: "myorganization",
	ValidAudiences: []string{
		"123123123123123123123123123123123123123",
	},
	
	// Whenever a request is blocked because of invalid or missing authentication,
	// LDAP group conditions not met or custom checks failing,
	// a default error response will be returned in JSON.
	//
	// You can change the way these errors are handled by providing a ErrorResponseHandler.
	// it should call a finalization method such as AbortWithStatusJSON.
	//
	// The ErrorResponseHandler function will be invoked with the request context,
	// the status error (either 401 or 403) and a non-nil error.
	ErrorResponseHandler: func(c *gin.Context, status int, err error) {
		c.AbortWithStatusJSON(
			status,
			fmt.Sprintf("customized error response (original error: %v)", err),
		)
	},
})
```

### Customize token lookup

```go
cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
	TeamDomain: "myorganization",
	ValidAudiences: []string{
		"123123123123123123123123123123123123123",
	},
	
	// If for some reason you want to provide the Access header
	// under a different header or with a different mechanism,
	// you can provide the TokenExtractFunc parameter.
	//
	// The function should look for an authorization token wherever you need
	// in the request, and return it.
	// If no token was found you should return an empty string and a nil error.
	// The request will be aborted if the function returns a non-nil error.
	TokenExtractFunc: func(c *gin.Context) (string, error) {
		h := c.Request.Header.Get("X-Custom-Auth-Header")
		if h != "" {
			return h, nil
		}
		cookie, err := c.Request.Cookie("X-Auth-Cookie")
		if cookie != nil && err != nil {
			return cookie.Value, nil
		}
		return "", nil
	},
})
```

### Customize caching

```go
cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
TeamDomain: "myorganization",
ValidAudiences: []string{
"123123123123123123123123123123123123123",
},

// By default principals authenticated from a token are cached in memory
// for a short duration.
// You can disable the caching mechanism by providing the DisableCache parameter.
DisableCache: false,

// By default principals authenticated from a token are cached in memory
// for 5 minutes.
// You can change this duration with the CacheTTL parameter.
CacheTTL: 2 * time.Minute,
})
```

### Mock for development purposes

You can provide a custom `AuthenticationFunc` if you want to mock authentication for development purposes.

```go
settings := &gincloudflareaccess.Config{
	TeamDomain: "myorganization",
	ValidAudiences: []string{
		"123123123123123123123123123123123123123",
	},
}

if (inDevelopment) {
	settings.AuthenticationFunc = func(ctx context.Context, _ string) (*CloudflareAccessPrincipal, error) {
		return &CloudflareAccessPrincipal{
			Identity: &CloudflareIdentity{
				Email: "user@mock.com",
				Name:  "some mocked user",
				Groups: []CloudflareIdentityGroup{
					{
						Id:    "group0",
						Name:  "Some Group",
						Email: "somegroup@mock.com",
					},
				},
			},
			Email: "user@mock.com",
		}, nil
	}
}

cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(settings)
```

You might also pass both `AuthenticationFunc` and `TokenExtractFunc` to have a more dynamic mocking logic:

```go
settings := &gincloudflareaccess.Config{
	TeamDomain: "myorganization",
	ValidAudiences: []string{
		"123123123123123123123123123123123123123",
	},
}

if (inDevelopment) {
	settings.TokenExtractFunc = func(c *gin.Context) (string, error) {
		// the content of X-Mocked-Auth will be passed as 'inputFromHeader' to the AuthenticationFunc
		return c.Request.Header.Get("X-Mocked-Auth"), nil
	}
	
	settings.AuthenticationFunc = func(ctx context.Context, inputFromHeader string) (*CloudflareAccessPrincipal, error) {
		return &CloudflareAccessPrincipal{
			Identity: &CloudflareIdentity{
				Email: inputFromHeader + "@mock.com",
				Name:  "user " + inputFromHeader,
				Groups: []CloudflareIdentityGroup{
					{
						Id:    "group0",
						Name:  "Some Group",
						Email: "somegroup@mock.com",
					},
				},
			},
			Email: inputFromHeader + "@mock.com",
		}, nil
	}
}

cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(settings)
```

## Full example

```go
package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	gincloudflareaccess "github.com/fabiofenoglio/gin-cloudflare-access"
	"github.com/gin-gonic/gin"
)

func main() {

	cfAccess := gincloudflareaccess.NewCloudflareAccessMiddleware(&gincloudflareaccess.Config{
		// TeamDomain is the name of your team.
		//
		// it's the third-level domain of your authentication portal,
		// for instance if your login page is https://organization.cloudflareaccess.com
		// then your TeamDomain is "organization"{
		TeamDomain: "organization",

		// Every Access Policy created under the Access or Team portal
		// will come with a specific Audience Tag.
		//
		// You should provide at least one audience tag
		// but you can support as many policies as you want by providing
		// multiple audience tags.
		ValidAudiences: []string{
			"123123123123123123123123123123123123123",
			"456456456456456456456456456456456456456",
		},

		// By default principals authenticated from a token are cached in memory
		// for a short duration.
		// You can disable the caching mechanism by providing the DisableCache parameter.
		DisableCache: false,

		// By default principals authenticated from a token are cached in memory
		// for 5 minutes.
		// You can change this duration with the CacheTTL parameter.
		CacheTTL: 2 * time.Minute,

		// If for some reason you want to provide the Access header
		// under a different header or with a different mechanism,
		// you can provide the TokenExtractFunc parameter.
		//
		// The function should look for an authorization token wherever you need
		// in the request, and return it.
		// If no token was found you should return an empty string and a nil error.
		// The request will be aborted if the function returns a non-nil error.
		TokenExtractFunc: func(c *gin.Context) (string, error) {
			h := c.Request.Header.Get("X-Custom-Auth-Header")
			if h != "" {
				return h, nil
			}
			cookie, err := c.Request.Cookie("X-Auth-Cookie")
			if cookie != nil && err != nil {
				return cookie.Value, nil
			}
			return "", nil
		},

		// Whenever a request is blocked because of invalid or missing authentication,
		// LDAP group conditions not met or custom checks failing,
		// a default error response will be returned in JSON.
		//
		// You can change the way these errors are handled by providing a ErrorResponseHandler.
		// it should call a finalization method such as AbortWithStatusJSON.
		//
		// The ErrorResponseHandler function will be invoked with the request context,
		// the status error (either 401 or 403) and a non-nil error.
		ErrorResponseHandler: func(c *gin.Context, status int, err error) {
			c.AbortWithStatusJSON(
				status,
				fmt.Sprintf("customized error response (original error: %v)", err),
			)
		},
	})

	r := gin.Default()

	// plug in authenticator at the root level
	// this middleware will read the authorization header or cookies
	// and, if provided, will validate and authenticate the user.
	//
	// invalid credentials and expired tokens will cause an immediate abort.
	//
	// note that, by itself, this middleware does not prevent
	// unauthenticated access nor perform any check on the authentication result
	// other than blocking invalid credentials.
	// additionals check have to be enabled with the .Require...() middlewares
	// that you'll see in the following lines.
	r.Use(cfAccess.AuthenticationMiddleware())

	// this route will not require authentication
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	// let's declare a sample handler to be reused from the following routes
	helloHandler := func(c *gin.Context) {
		// you can retrieve the principal from the gin.Context using GetPrincipal
		// mind that GetPrincipal may return nil for unauthenticated requests
		principal := gincloudflareaccess.GetPrincipal(c)

		// reply with details about the authenticated principal
		c.JSON(http.StatusOK, principal)
	}

	// require authenticated users for all routes under /secured/**
	// by plugging in the RequireAuthenticated middleware
	//
	// note that as other middlewares, .RequireAuthenticated() can be applied to a single route,
	// to a route group or to the whole router
	authorized := r.Group("/secured", cfAccess.RequireAuthenticated())

	// this routes will require authentication
	// (inherited from the 'authorized' route group)
	authorized.GET("/some-protected-route", helloHandler)
	authorized.GET("/other-protected-route", helloHandler)

	// this route will require a custom condition to be evaluated on each request
	//
	// the .Require() middleware can be used to implements custom checks:
	// it receives the request context and the authenticated principals
	// and it can return a non-nil error to abort the request.
	//
	// when the provided function returns an error,
	// the default behavior for Forbidden requests executes, so
	// if a ErrorResponseHandler has been provided it will be
	// invoked with the returned error and a 403 status code.
	//
	// note that as other middlewares, .Require() can be applied to a single route,
	// to a route group or to the whole router
	r.GET("/require-custom", cfAccess.Require(func(c *gin.Context, principal *gincloudflareaccess.CloudflareAccessPrincipal) error {
		if principal == nil {
			return errors.New("auth required")
		}
		if c.Request.Header.Get("X-Mock-Allow") != principal.Identity.Email {
			return errors.New("required custom header not valid")
		}
		return nil
	}), helloHandler)

	// this route will require authenticated users belonging to
	// a specific LDAP group.
	//
	// note that as other middlewares, .RequireGroup() can be applied to a single route,
	// to a route group or to the whole router
	r.GET("/require-group", cfAccess.RequireGroup("group0@organization.com"), helloHandler)

	// this route will require authenticated users belonging to
	// everyone of the specified LDAP groups.
	//
	// note that as other middlewares, .RequireAllGroups() can be applied to a single route,
	// to a route group or to the whole router
	r.GET("/require-all-groups", cfAccess.RequireAllGroups([]string{
		"group0@organization.com",
		"group1@organization.com",
	}), helloHandler)

	// this route will require authenticated users belonging to
	// at least one of the specified LDAP groups.
	//
	// note that as other middlewares, .RequireAnyGroup() can be applied to a single route,
	// to a route group or to the whole router
	r.GET("/require-any-group", cfAccess.RequireAnyGroup([]string{
		"group1@organization.com",
		"groupX@organization.com",
	}), helloHandler)

	// this route will require authentication
	r.GET("/auth-demo", cfAccess.RequireAuthenticated(), func(c *gin.Context) {
		// you can retrieve the principal with the GetPrincipal method.
		// mind that GetPrincipal may return nil for unauthenticated requests
		principal := gincloudflareaccess.GetPrincipal(c)

		if principal == nil {
			panic("didn't expect a nil principal")
		}

		// you can manually check if the user belongs to
		// a/all/any specified LDAP groups with the helper methods:
		inGroup := gincloudflareaccess.PrincipalInGroup(c, "somegroup@organization.com")
		if !inGroup {
			panic("go away")
		}
	})

	// run the server and listen on http://localhost:9000
	err := r.Run(":9000")
	if err != nil {
		panic(err)
	}
}
```

## Available data for authenticated principals

```json
{
    "token":{
        "iss":"https://organization.cloudflareaccess.com",
        "aud":[
            "456456456456456456456456456456456456456456"
        ],
        "sub":"79ea41a5-d90c-45b0-83b7-98bab753c982",
        "exp":"2022-01-23T10:30:51+01:00",
        "iat":"2022-01-22T10:30:51+01:00",
        "email":"user@organization.com",
        "identity_nonce":"dskgwjegowegjo",
        "country":"IT"
    },
    "identity":{
        "id":"1231231241241212312",
        "name":"User Name",
        "email":"user@organization.com",
        "user_uuid":"79ea41a5-d90c-45b0-83b7-98bab753c982",
        "account_id":"cee91dbebfad4e93be5df3616215e207",
        "ip":"1.2.3.4",
        "auth_status":"NONE",
        "common_name":"",
        "service_token_id":"",
        "service_token_status":false,
        "is_warp":false,
        "is_gateway":false,
        "version":0,
        "device_sessions":{},
        "iat":1642843851,
        "idp":{
            "id":"891cfb5e-7de3-43e4-9929-4ae34ab6e110",
            "type":"google-apps"
        },
        "geo":{
            "country":"IT"
        },
        "groups":[
            {
                "id":"f81e269a598341f8807028463abb6eea",
                "name":"Administrators",
                "email":"administrators@organization.com"
            },
            {
                "id":"865c98799d304008b6258b736321b395",
                "name":"Support",
                "email":"support@organization.com"
            }
        ]
    },
    "email":"user@organization.com"
}
```
package design

import (
	. "github.com/goadesign/goa/design"
	. "github.com/goadesign/goa/design/apidsl"
)

var JWT = JWTSecurity("jwt", func() {
	Header("Authorization")
	Scope("api:access", "API access") // Define "api:access" scope
})

// Resource jwt uses the JWTSecurity security scheme.
var _ = Resource("jwt", func() {
	Description("This resource uses JWT to secure its endpoints")
	DefaultMedia(SuccessMedia)

	Security(JWT, func() { // Use JWT to auth requests to this endpoint
		Scope("api:access") // Enforce presence of "api" scope in JWT claims.
	})

	Action("secure", func() {
		Description("This action is secured with the jwt scheme")
		Routing(GET("/jwt"))
		Params(func() {
			Param("fail", Boolean, "Force auth failure via JWT validation middleware")
		})
		Response(OK)
		Response(Unauthorized)
	})

	Action("unsecure", func() {
		Description("This action does not require auth")
		Routing(GET("/jwt/unsecure"))
		NoSecurity() // Override the need for auth
		Response(OK)
	})
})

var SuccessMedia = MediaType("application/vnd.goa.examples.security.success", func() {
	Description("The common media type to all request responses for this example")
	TypeName("Success")
	Attributes(func() {
		Attribute("ok", Boolean, "Always true")
		Required("ok")
	})
	View("default", func() {
		Attribute("ok")
	})
})

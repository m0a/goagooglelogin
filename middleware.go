package goagooglelogin

import (
	"context"
	"net/http"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
)

// ForceFail is a middleware illustrating the use of validation middleware with JWT auth.  It checks
// for the presence of a "fail" query string and fails validation if set to the value "true".
func forceFail() goa.Middleware {
	errValidationFailed := goa.NewErrorClass("validation_failed", 401)
	forceFail := func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			if f, ok := req.URL.Query()["fail"]; ok {
				if f[0] == "true" {
					return errValidationFailed("forcing failure to illustrate Validation middleware")
				}
			}
			return h(ctx, rw, req)
		}
	}
	fm, _ := goa.NewMiddleware(forceFail)
	return fm
}

// NewJWTMiddleware creates a middleware that checks for the presence of a JWT Authorization header
// and validates its content. A real app would probably use goa's JWT security middleware instead.
//
// Note: the code below assumes the example is compiled against the master branch of goa.
// If compiling against goa v1 the call to jwt.New needs to be:
//
//    middleware := jwt.New(keys, ForceFail(), app.NewJWTSecurity())
func NewJWTMiddleware(conf *GoaGloginConf, newJWTSecurity *goa.JWTSecurity) goa.Middleware {
	if conf != nil {
		conf = &DefaultGoaGloginConf
	}
	keys := []jwt.Key{conf.LoginSigned}
	return jwt.New(jwt.NewSimpleResolver(keys), forceFail(), newJWTSecurity)
}

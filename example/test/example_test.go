package test

import (
	"testing"

	"github.com/goadesign/goa"

	"github.com/m0a/goagooglelogin"
	"github.com/m0a/goagooglelogin/example/app"
	"github.com/m0a/goagooglelogin/example/app/test"
	"github.com/m0a/goagooglelogin/example/controllers"
)

func TestSecureJWTOK(t *testing.T) {
	service := goa.New("example")
	service.Use(goagooglelogin.New(service))
	app.UseJWTMiddleware(service, goagooglelogin.NewJWTMiddleware(nil, app.NewJWTSecurity()))
	accounts := map[string]controllers.Account{
		"001": controllers.Account{
			Name:         "m0a",
			GoogleUserID: "001",
			Email:        "m0a@github.com",
		},
	}

	claims := goagooglelogin.MakeClaim("sample", "001", 20)
	service.Context = goagooglelogin.WithJWTClaims(service.Context, claims)

	control := controllers.NewJWTController(service, &accounts)
	test.SecureJWTOK(t, service.Context, service, control)
}

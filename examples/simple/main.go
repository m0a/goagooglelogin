package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	oauth2 "google.golang.org/api/oauth2/v2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
	"github.com/m0a/goagooglelogin"
	"github.com/m0a/goagooglelogin/examples/simple/app"
	"github.com/m0a/goagooglelogin/examples/simple/controllers"
)

var (
	// ErrUnauthorized is the error returned for unauthorized requests.
	ErrUnauthorized = goa.NewErrorClass("unauthorized", 401)
)

func main() {
	// Create service
	service := goa.New("Secure API")

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())

	accounts := map[string]controllers.Account{}

	conf := &goagooglelogin.DefaultGoaGloginConf
	conf.LoginSigned = "eeee33344445"
	conf.StateSigned = "sddwsdfaseq2"
	conf.GoogleClientID = os.Getenv("OPENID_GOOGLE_CLIENT")
	conf.GoogleClientSecret = os.Getenv("OPENID_GOOGLE_SECRET")

	conf.CreateClaims = func(googleUserID string,
		userinfo *oauth2.Userinfoplus, tokenInfo *oauth2.Tokeninfo, r *http.Request) (claims jwt.Claims, err error) {
		resp, err := http.Get(userinfo.Picture)
		if err != nil {
			return nil, err

		}
		defer resp.Body.Close()
		picture, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		fmt.Println(len(picture))

		// sample save code
		_, ok := accounts[googleUserID]
		if !ok {
			account := controllers.Account{
				GoogleUserID: googleUserID,
				Image:        picture,
				Email:        userinfo.Email,
				Name:         userinfo.Name,
				Created:      time.Now(),
			}
			accounts[googleUserID] = account
		}

		return goagooglelogin.MakeClaim("api:access", googleUserID, 10), nil
	}

	service.Use(goagooglelogin.WithConfig(service, conf))

	// Mount security middlewares
	app.UseJWTMiddleware(service, goagooglelogin.NewJWTMiddleware(conf, app.NewJWTSecurity()))

	// Mount "JWT" controller
	c1 := controllers.NewJWTController(service, &accounts)
	app.MountJWTController(service, c1)

	c2 := controllers.NewServeController(service)
	app.MountServeController(service, c2)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}
}

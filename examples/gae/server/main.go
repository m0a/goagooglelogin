package server

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"google.golang.org/appengine/urlfetch"

	oauth2 "google.golang.org/api/oauth2/v2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
	"github.com/m0a/goagooglelogin"
	"github.com/m0a/goagooglelogin/examples/gae/app"
	"github.com/m0a/goagooglelogin/examples/gae/controllers"
)

var (
	// ErrUnauthorized is the error returned for unauthorized requests.
	ErrUnauthorized = goa.NewErrorClass("unauthorized", 401)
)

func init() {
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

	conf.CreateClaims = func(
		ctx context.Context,
		googleUserID string,
		userinfo *oauth2.Userinfoplus,
		tokenInfo *oauth2.Tokeninfo) (claims jwt.Claims, err error) {

		client := urlfetch.Client(ctx)

		resp, err := client.Get(userinfo.Picture)
		if err != nil {
			return nil, err

		}
		defer resp.Body.Close()
		picture, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		// sample save code
		_, ok := accounts[googleUserID]
		if !ok {
			account := controllers.Account{
				GoogleUserID: googleUserID,
				Picture:      picture,
				Email:        userinfo.Email,
				Name:         userinfo.Name,
				Created:      time.Now(),
			}
			accounts[googleUserID] = account
		}

		return goagooglelogin.MakeClaim("api:access", googleUserID, 10), nil
	}

	// Mount security middlewares
	app.UseJWTMiddleware(service, goagooglelogin.NewJWTMiddleware(conf, app.NewJWTSecurity()))

	goagooglelogin.MountControllerWithConfig(service, conf)
	// Mount "JWT" controller
	c1 := controllers.NewJWTController(service, &accounts)
	app.MountJWTController(service, c1)

	c2 := controllers.NewServeController(service)
	app.MountServeController(service, c2)

	// Setup HTTP handler
	http.HandleFunc("/", service.Mux.ServeHTTP)
}

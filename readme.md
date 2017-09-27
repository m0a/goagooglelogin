
# googlelogin goa middleware

simple google login midleware for ``goa``

please check example [standard](https://github.com/m0a/goagooglelogin/tree/master/examples/simple) or [GAE/go sample](https://github.com/m0a/goagooglelogin/tree/master/examples/gae)


# how to use

## setting desgin

require setup JWTSecurity

```go

var JWT = JWTSecurity("jwt", func() {
	Header("Authorization")
	Scope("api:access", "API access") // Define "api:access" scope
})

// use JWT securety

var _ = Resource("sample", func() {
	Description("This resource uses JWT to secure its endpoints")
	DefaultMedia(SuccessMedia)

	// Use JWT to auth requests to this endpoint
	Security(JWT, func() { 
		Scope("api:access")
	})

	Action("secure", func() {
		Description("This action is secured with the jwt scheme")
		Routing(GET("/jwt"))
		Response(OK, SecureMedia)
		Response(Unauthorized)
	})

})

```

## edit main.go

### setup conf

required GoogleClientID and GoogleClientSecret and CreateClaims

```go

	// for sample savecode
	accounts := map[string]controllers.Account{} 

	conf := &goagooglelogin.DefaultGoaGloginConf
	conf.GoogleClientID = os.Getenv("OPENID_GOOGLE_CLIENT")
	conf.GoogleClientSecret = os.Getenv("OPENID_GOOGLE_SECRET")

	conf.CreateClaims = func(googleUserID string,
		userinfo *oauth2.Userinfoplus, tokenInfo *oauth2.Tokeninfo, ctx context.Context) (claims jwt.Claims, err error) {
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

```

### use midlaware and mount controllers

```go
	app.UseJWTMiddleware(service, goagooglelogin.NewJWTMiddleware(conf, app.NewJWTSecurity()))

	goagooglelogin.MountControllerWithConfig(service, conf)
```

## edit controllers

get googleID from GoogleIDByJWTContext.

```go
func (c *SampleController) Secure(ctx *app.SampleJWTContext) error {

	googleID, err := goagooglelogin.GoogleIDByJWTContext(ctx)

	if err != nil {
		return ctx.Unauthorized()
	}

	if c.Accounts == nil {
		return ctx.Unauthorized()
	}
	account, ok := (*c.Accounts)[googleID]
	if !ok {
		return ctx.Unauthorized()
	}

	img := base64.StdEncoding.EncodeToString(account.Image)
	res := app.GoaExamplesSecuritySecure{
		Name:  &account.Name,
		Email: &account.Email,
		Image: &img,
	}
	return ctx.OK(&res)
}
```
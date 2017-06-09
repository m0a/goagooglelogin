
# googlelogin goa middleware

goaでお手軽google loginを行うミドルウェアを作ってみました。


goaで手軽にwebAPIをつくれるのはいいのですが、ユーザ認証が意外と面倒です。
かと言って個人開発でauth0とか使ってられないし。

googleアカウントで認証を行いtokenを発行して以降、それを使って
通信を行いたいです。できるだけ手軽に。


そういうのが簡単に実現できるミドルウェアを作ってみました。
またセキュリテイ上の懸念があるようでしたらご指摘いただければ幸いです。


以下のシーケンスでやり取りします。
stateのチェックとapiと通信を行うためのトークンとして
JWTを使っています。

*JWTとはjsonをbase64エンコードしたものですがそれに署名を付けて改ざんの検知ができるようにしたものです。*



![js-sequence-diagrams_by_bramp.png](https://qiita-image-store.s3.amazonaws.com/0/3844/56cd01bd-6393-cde6-bfee-1fe89de78578.png "js-sequence-diagrams_by_bramp.png")


最初のリダイレクトの際にstateに本来はランダムな文字列を格納するのですが
今回はそこにJWTを仕込んでいます。
そうすることでstate用のランダム文字列をdbに一時保存する処理が不要となります。


# 実際の使い方
先ず今回作ったミドルウェアを読み込みます

```
$ go get github.com/m0a/goagooglelogin
```

先ずはJWTをサポートする設計を行います

```design/design.go
package design

import (
	. "github.com/goadesign/goa/design"
	. "github.com/goadesign/goa/design/apidsl"
)

var JWT = JWTSecurity("jwt", func() {
	Header("Authorization")
	Scope("api:access", "API access") // Define "api:access" scope
})

// web static file serve
var _ = Resource("serve", func() {
	Files("/", "./static/index.html")
	Files("/static/*filepath", "./static")
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
		Response(OK, SecureMedia)
		Response(Unauthorized)
	})

	Action("unsecure", func() {
		Description("This action does not require auth")
		Routing(GET("/jwt/unsecure"))
		NoSecurity() // Override the need for auth
		Response(OK)
	})
})

var SecureMedia = MediaType("application/vnd.goa.examples.security.secure+json", func() {
	Attributes(func() {
		Attribute("Name", String)
		Attribute("Email", String)
		Attribute("Image", String)
	})
	View("default", func() {
		Attribute("Name")
		Attribute("Email")
		Attribute("Image")
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


```


上記はJWTの例の丸コピです。api設計としては

| methods | エンドポイント | 目的|
|--------|--------|-----|
| get  |http://XXX/api/jwt |セキュリティ有り |
| get|http://XXX/api/jwt/unsecure |セキュリティ無し|

となっています。http://XXX/api/jwt にアクセスしたら自分の情報をdbから拾いに行くようにします。


# 実装

先ずはdbとしてメモリにためておくように構造体を作っておきます

```models.go
package main

import "time"

type Account struct {
	GoogleUserID string
	Image        []byte
	Email        string
	Name         string
	Created      time.Time
}
```

実際の実装は以下のとおりです


```main.go
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
	"github.com/m0a/goagooglelogin/example/app"
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

	accounts := map[string]Account{}

	conf := &goagooglelogin.DefaultGoaGloginConf
	conf.LoginSigned = "xsdsafasd"
	conf.StateSigned = "sddwaseq2"
	conf.GoogleClientID = os.Getenv("OPENID_GOOGLE_CLIENT")
	conf.GoogleClientSecret = os.Getenv("OPENID_GOOGLE_SECRET")

	conf.CreateClaims = func(googleUserID string,
		userinfo *oauth2.Userinfoplus, tokenInfo *oauth2.Tokeninfo) (claims jwt.Claims, err error) {
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
			account := Account{
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
	c1 := NewJWTController(service, &accounts)
	app.MountJWTController(service, c1)

	c2 := NewServeController(service)
	app.MountServeController(service, c2)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}
}

```

順に説明しますと

```go:main.go

conf := &goagooglelogin.DefaultGoaGloginConf
	conf.LoginSigned = "xsdsafasd"
	conf.StateSigned = "sddwaseq2"
	conf.GoogleClientID = os.Getenv("OPENID_GOOGLE_CLIENT")
	conf.GoogleClientSecret = os.Getenv("OPENID_GOOGLE_SECRET")

	conf.CreateClaims = func(googleUserID string,
		userinfo *oauth2.Userinfoplus, tokenInfo *oauth2.Tokeninfo) (claims jwt.Claims, err error) {
		/* 省略 */
	}
```

にて各種設定を行っています

``conf.LoginSigned`` と ``conf.StateSigned``はそれぞれJWTを作る際のキーとなります。

``conf.GoogleClientID``と``conf.GoogleClientSecret``はGoogleアカントアクセスのためのキーとシークレットとなります。

``conf.CreateClaims``にTokenのClaim作成処理とDBへの保存処理を記述しておきます。
Claim作成処理は``goagooglelogin.MakeClaim``でほとんど行いますので、
基本的にはDBの保存処理を書くことになります。

上記設定は一つの構造体に集約してます

```go
	GoaGloginConf struct {
		LoginURL           string // defualt: /login
		CallbackURL        string // default: /oauth2callback
		StateSigned        string // state JWT key
		LoginSigned        string // login JWT key
		GoogleClientID     string
		GoogleClientSecret string
		CreateClaims       func(googleUserID string, userinfo *oauth2.Userinfoplus, tokenInfo *oauth2.Tokeninfo) (jwt.Claims, error)
	}
```

``loginURL``と``CallbackURL``はデフォルトのまま使ったほうがいいと思います。

上記設定であれば最初に`/lgoin?next_url=/`でログイン処理が開始します。
``next_url``はログイン完了後sessionStorageにトークンを保存した後にリダイレクトするurlとなります。
あとはコールバック先としてログイン画面表示後に、``/oauth2callback``に遷移します。


## コントローラーからのアクセス

変更点のみ記述します

```
// NewJWTController creates a jwt controller.
func NewJWTController(service *goa.Service, ac *map[string]Account) *JWTController {
	return &JWTController{
		Controller: service.NewController("JWTController"),
		Accounts:   ac,
	}
}

// Secure runs the secure action.
func (c *JWTController) Secure(ctx *app.SecureJWTContext) error {
	jwtContext := jwt.ContextJWT(ctx)
	claims, ok := jwtContext.Claims.(jwtgo.MapClaims)
	if !ok {
		return ctx.Unauthorized()
	}
	googleID, ok := claims["sub"].(string)
	if !ok {
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

以下の処理にてJWTからgoogleIDを取得します。

```
	jwtContext := jwt.ContextJWT(ctx)
	claims, ok := jwtContext.Claims.(jwtgo.MapClaims)
	if !ok {
		return ctx.Unauthorized()
	}
	googleID, ok := claims["sub"].(string)
	if !ok {
		return ctx.Unauthorized()
	}

```

あとはDBからそのIDを使って必要な情報を引き出すことで取得します。
この実装全体は以下においています

https://github.com/m0a/goagooglelogin/tree/master/example



# 参考情報

あとで記述












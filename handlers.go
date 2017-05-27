package goagooglelogin

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/oauth2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
	v2 "google.golang.org/api/oauth2/v2"
)

var (
	conf = oauth2.Config{
		ClientID:     os.Getenv("OPENID_GOOGLE_CLIENT"),
		ClientSecret: os.Getenv("OPENID_GOOGLE_SECRET"),
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://www.googleapis.com/oauth2/v4/token",
		},
	}
)

// MakeAuthHandler is created redirectURL and access redirectURL
func MakeAuthHandler(service *goa.Service, loginConf *GoaGloginConf) goa.MuxHandler {
	return func(w http.ResponseWriter, r *http.Request, _ url.Values) {
		redirectURL := r.URL
		redirectURL.Path = loginConf.CallbackURL
		redirectURL.Host = r.Host
		if r.TLS == nil {
			redirectURL.Scheme = "http"
		} else {
			redirectURL.Scheme = "https"
		}

		conf.RedirectURL = redirectURL.String()
		service.LogInfo("mount", "middleware", "goagooglelogin", "redirectURL.String()", redirectURL.String())
		claims := &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(30) * time.Second).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		state, err := token.SignedString([]byte(loginConf.StateSigned))
		if err != nil {
			service.LogInfo("mount", "middleware", "goagooglelogin", "state", state)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		url := conf.AuthCodeURL(state)
		service.LogInfo("mount", "middleware", "goagooglelogin", "url", url)
		http.Redirect(w, r, url, 302)
	}
}

func DefaultSaveUserInfo(googleUserID string, userInfo *v2.Userinfoplus, tokenInfo *v2.Tokeninfo) error {

	resp, err := http.Get(userInfo.Picture)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	picture, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println(len(picture))

	// account := &models.Account{}
	// account, err = models.AccountByGoogleUserID(option.db, googleUserID)
	// if err != nil {
	// 	account = &models.Account{
	// 		GoogleUserID: googleUserID,
	// 		Image:        picture,
	// 		Email:        userInfo.Email,
	// 		Name:         userInfo.Name,
	// 		Created:      time.Now(),
	// 	}
	// 	err = account.Insert(option.db)
	// 	if err != nil {
	// 		http.Error(w, err.Error(), http.StatusUnauthorized)
	// 		return
	// 	}
	// }

	return nil
}

// MakeOauth2callbackHandler callback url and state check and get AccessToken
func MakeOauth2callbackHandler(service *goa.Service, loginConf *GoaGloginConf) goa.MuxHandler {
	return func(w http.ResponseWriter, r *http.Request, _ url.Values) {

		if loginConf == nil {
			loginConf = &DefaultGoaGloginConf
		}

		state := r.FormValue("state")
		t, err := jwt.Parse(state, func(*jwt.Token) (interface{}, error) {
			return []byte(loginConf.StateSigned), nil
		})
		if !t.Valid {
			http.Error(w, "state is invalid.", http.StatusUnauthorized)
			return
		}

		// 認証コードを取得します
		code := r.FormValue("code")
		context := context.Background()
		// 認証コードからtokenを取得します
		tok, err := conf.Exchange(context, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		// tokenが正しいことを確認します
		if tok.Valid() == false {
			http.Error(w, "token is invalid.", http.StatusUnauthorized)
			return
		}

		// oauth2 clinet serviceを取得します
		oAuthservice, err := v2.New(conf.Client(context, tok))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// token情報を取得します
		// ここにEmailやUser IDなどが入っています
		tokenInfo, err := oAuthservice.Tokeninfo().AccessToken(tok.AccessToken).Context(context).Do()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		userInfo, err := oAuthservice.Userinfo.Get().Do()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if loginConf.SaveUserInfo == nil {
			http.Error(w, "expect define SaveUserInfo", http.StatusUnauthorized)
			return
		}

		// resp, err := http.Get(userInfo.Picture)
		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusUnauthorized)
		// 	return
		// }

		// defer resp.Body.Close()
		// picture, err := ioutil.ReadAll(resp.Body)
		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusUnauthorized)
		// 	return
		// }

		googleUserID := tokenInfo.UserId
		// service.LogInfo("mount", "middleware", "MakeOauth2callbackHandler", "SaveUserInfo googleUserID")
		service.LogInfo("mount", "middleware", "MakeOauth2callbackHandler", "SaveUserInfo googleUserID", googleUserID)
		err = loginConf.SaveUserInfo(googleUserID, userInfo, tokenInfo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// account := &models.Account{}
		// account, err = models.AccountByGoogleUserID(option.db, googleUserID)
		// if err != nil {
		// 	account = &models.Account{
		// 		GoogleUserID: googleUserID,
		// 		Image:        picture,
		// 		Email:        userInfo.Email,
		// 		Name:         userInfo.Name,
		// 		Created:      time.Now(),
		// 	}
		// 	err = account.Insert(option.db)
		// 	if err != nil {
		// 		http.Error(w, err.Error(), http.StatusUnauthorized)
		// 		return
		// 	}
		// }

		// claims := &jwt.StandardClaims{
		// 	ExpiresAt: time.Now().Add(time.Duration(30) * time.Second).Unix(),
		// }
		// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// state, err := token.SignedString([]byte(loginConf.StateSigned))

		// token := jwt.New(jwt.SigningMethodHS512)
		inXm := time.Now().Add(time.Duration(loginConf.ExpireMinute) * time.Minute).Unix()
		claims := jwt.MapClaims{
			"iss":    "goagooglelogin",      // who creates the token and signs it
			"exp":    inXm,                  // time when the token will expire (X minutes from now)
			"jti":    uuid.NewV4().String(), // a unique identifier for the token
			"iat":    time.Now().Unix(),     // when the token was issued/created (now)
			"sub":    googleUserID,          // the subject/principal is whom the token is about
			"scopes": "api:access",          // token scope - not a standard claim
		}

		signedToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		signedTokenStr, err := signedToken.SignedString([]byte(loginConf.LoginSigned))
		if err != nil {
			http.Error(w, err.Error()+"oh! no", http.StatusUnauthorized)
			return
		}

		tmpl, err := template.New("save_token").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<script>
			signedtoken ="{{.SignedToken}}";
			sessionStorage.setItem('signedtoken',signedtoken);
			let data = sessionStorage.getItem('signedtoken');
			location.href = '{{.RedirectURL}}';
		</script>	
	</head>
</html>
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		type templateItem struct {
			SignedToken string
			RedirectURL string
		}

		items := templateItem{
			SignedToken: signedTokenStr,
			RedirectURL: "/",
		}

		err = tmpl.Execute(w, items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

	}
}

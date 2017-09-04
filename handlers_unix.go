// +build !appengine

package goagooglelogin

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	v2 "google.golang.org/api/oauth2/v2"
)

func makeOauth2callbackHandler(service *goa.Service, loginConf *GoaGloginConf) goa.MuxHandler {
	return func(w http.ResponseWriter, r *http.Request, _ url.Values) {

		if loginConf == nil {
			loginConf = &DefaultGoaGloginConf
		}

		state := r.FormValue("state")
		t, err := jwtgo.Parse(state, func(*jwtgo.Token) (interface{}, error) {
			return []byte(loginConf.StateSigned), nil
		})
		if err != nil {
			http.Error(w, "jwt.Parse err.", http.StatusUnauthorized)
			return
		}
		if !t.Valid {
			http.Error(w, "state is invalid.", http.StatusUnauthorized)
			return
		}

		mapClaims, ok := t.Claims.(jwtgo.MapClaims)
		if !ok {
			http.Error(w, "claims is invalid.", http.StatusUnauthorized)
			return
		}
		service.LogInfo("mount", "middleware", "makeOauth2callbackHandler", "mapClaims", fmt.Sprintf("%#v", mapClaims))
		temp, ok := mapClaims["redirect_url"]
		if !ok {
			http.Error(w, "mapClaims[redirect_url] is invalid.", http.StatusUnauthorized)
			return
		}

		redirectURL, ok := temp.(string)
		if !ok {
			http.Error(w, "mapClaims[redirect_url] string is invalid.", http.StatusUnauthorized)
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

		if loginConf.CreateClaims == nil {
			http.Error(w, "expect define SaveUserInfo", http.StatusUnauthorized)
			return
		}

		googleUserID := tokenInfo.UserId
		service.LogInfo("mount", "middleware", "MakeOauth2callbackHandler", "CreateClaims googleUserID", googleUserID)
		claims, err := loginConf.CreateClaims(googleUserID, userInfo, tokenInfo, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// signedToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		// signedTokenStr, err := signedToken.SignedString([]byte(loginConf.LoginSigned))
		signedTokenStr, err := CreateSignedToken(claims, loginConf)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
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
			let token = sessionStorage.getItem('signedtoken');

			let extensionIds = JSON.parse({{.ExtensionIDs}});
			for (let id of extensionIds) {
				console.log('send to: '+ id + ' jwt: '+ token);
				chrome.runtime.sendMessage(id, { jwt: token });
			}

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
			SignedToken  string
			RedirectURL  string
			ExtensionIDs string
		}

		extensionIds, err := json.Marshal(loginConf.ExtensionIDs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		items := templateItem{
			SignedToken:  signedTokenStr,
			RedirectURL:  redirectURL,
			ExtensionIDs: string(extensionIds),
		}

		err = tmpl.Execute(w, items)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

	}
}

package goagooglelogin

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jwtpkg "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
)

func getStateFromAuthHandler() string {
	service := goa.New("test")
	handler := makeAuthHandler(service, &DefaultGoaGloginConf)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, r.URL.Query())
	}))
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	str, err := ioutil.ReadAll(res.Body)
	index := strings.Index(string(str), "state=")
	index += 6
	str = str[index:]
	lastIndex := strings.LastIndex(string(str), "</li></ul></div><script")
	str = str[:lastIndex]
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	return string(str)
}
func TestAuthHandler(t *testing.T) {
	state := getStateFromAuthHandler()
	fmt.Printf("%s\n", state)
	var keyfunc jwtpkg.Keyfunc = func(_ *jwtpkg.Token) (interface{}, error) {
		return []byte(DefaultGoaGloginConf.StateSigned), nil
	}
	fmt.Println("state=", state)
	token, err := jwtpkg.Parse(state, keyfunc)
	if err != nil {
		t.Error(err)
	}
	if token.Valid {
		fmt.Println("is Valid", state)
	}
}

func makeCode() (string, error) {
	claim := MakeClaim("test", "gid", 10)
	token := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS512, claim)
	return token.SignedString([]byte(DefaultGoaGloginConf.LoginSigned))
}
func TestHandlers(t *testing.T) {
	service := goa.New("test")
	handler := makeOauth2callbackHandler(service, &DefaultGoaGloginConf)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, r.URL.Query())
	}))
	defer ts.Close()
	tsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Error(err)
	}
	q := tsURL.Query()
	code, err := makeCode()
	if err != nil {
		t.Error(err)
	}
	fmt.Println(code)
	q.Add("code", code)

	state := getStateFromAuthHandler()
	q.Add("state", state)

	tsURL.RawQuery = q.Encode()
	res, err := http.Get(tsURL.String())
	if err != nil {
		log.Fatal(err)
	}
	greeting, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", greeting)
	// handler(respRecord, request, request.URL.Query())
	// bytes, err := ioutil.ReadAll(respRecord.Body)
	// if err != nil {
	// fmt.Println(bytes)
	// }
}

package main

import (
	"fmt"
	"os"

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

	conf := &goagooglelogin.DefaultGoaGloginConf
	service.Use(goagooglelogin.WithConfig(service, conf))

	// Mount security middlewares
	app.UseJWTMiddleware(service, goagooglelogin.NewJWTMiddleware(conf, app.NewJWTSecurity()))

	// Mount "JWT" controller
	c3 := NewJWTController(service)
	// exitOnFailure(err)
	app.MountJWTController(service, c3)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}
}

// exitOnFailure prints a fatal error message and exits the process with status 1.
func exitOnFailure(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "[CRIT] %s", err.Error())
	os.Exit(1)
}

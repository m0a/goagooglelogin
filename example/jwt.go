package main

import (
	"github.com/goadesign/goa"

	"github.com/m0a/goagooglelogin/example/app"
)

// JWTController implements the jwt resource.
type JWTController struct {
	*goa.Controller
}

// NewJWTController creates a jwt controller.
func NewJWTController(service *goa.Service) *JWTController {
	return &JWTController{Controller: service.NewController("JWTController")}
}

// Secure runs the secure action.
func (c *JWTController) Secure(ctx *app.SecureJWTContext) error {
	// JWTController_Secure: start_implement

	// Put your logic here

	// JWTController_Secure: end_implement
	res := &app.Success{}
	return ctx.OK(res)
}

// Unsecure runs the unsecure action.
func (c *JWTController) Unsecure(ctx *app.UnsecureJWTContext) error {
	// JWTController_Unsecure: start_implement

	// Put your logic here

	// JWTController_Unsecure: end_implement
	res := &app.Success{}
	return ctx.OK(res)
}

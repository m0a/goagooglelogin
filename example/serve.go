package main

import (
	"github.com/goadesign/goa"
)

// ServeController implements the serve resource.
type ServeController struct {
	*goa.Controller
}

// NewServeController creates a serve controller.
func NewServeController(service *goa.Service) *ServeController {
	return &ServeController{Controller: service.NewController("ServeController")}
}

package main

import "time"

type Account struct {
	GoogleUserID string
	Image        []byte
	Email        string
	Name         string
	Created      time.Time
}

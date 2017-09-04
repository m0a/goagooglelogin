package controllers

import "time"

type Account struct {
	GoogleUserID string
	Picture      []byte
	Email        string
	Name         string
	Created      time.Time
}

package main

import "time"

// 	account = &models.Account{
// 		GoogleUserID: googleUserID,
// 		Image:        picture,
// 		Email:        userInfo.Email,
// 		Name:         userInfo.Name,
// 		Created:      time.Now(),
// 	}

type Account struct {
	GoogleUserID string
	Image        []byte
	Email        string
	Name         string
	Created      time.Time
}

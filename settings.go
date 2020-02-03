package jwtlib

import "os"

// Settings API settings
type Settings struct {
	PrivateKeyPath         string
	PublicKeyPath          string
	AccessTokenExpiration  int
	RefreshTokenExpiration int
}

var Properties *Settings = &Settings{
	PrivateKeyPath:         os.Getenv("PRIVATE_KEY_PATH"),
	PublicKeyPath:          os.Getenv("PUBLIC_KEY_PATH"),
	AccessTokenExpiration:  72,
	RefreshTokenExpiration: 72,
}

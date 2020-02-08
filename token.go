package jwtlib

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"os"
	"time"
)

type JWTAuth struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type JWTInfos struct {
	exp *time.Time
	iat *time.Time
	sub string
}

func Init() *JWTAuth {
	return &JWTAuth{
		privateKey: getPrivateKey(),
		PublicKey:  getPublicKey(),
	}
}

func (j *JWTInfos) GetUID() string {
	return j.sub
}

func (j *JWTInfos) IsValid() bool {
	return j.exp.Before(time.Now())
}

// IsAuthenticated check if the access token is valid
func (backend *JWTAuth) IsAuthenticated(token string) bool {
	infos, err := backend.ParseToken(token)
	if err != nil || infos.exp.Before(time.Now()) {
		return false
	}

	return true
}

// GenerateToken generate token
func (backend *JWTAuth) GenerateToken(uid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * time.Duration(Properties.AccessTokenExpiration)).Unix(),
		"iat": time.Now().Unix(),
		"sub": uid,
	})
	tokenString, err := token.SignedString(backend.privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (backend *JWTAuth) parseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return backend.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

func (backend *JWTAuth) ParseToken(token string) (*JWTInfos, error) {
	claims, err := backend.parseToken(token)
	if err != nil {
		return nil, err
	}
	infos := JWTInfos{
		exp: fromUnixTimestamp(int64(claims["exp"].(float64))),
		iat: fromUnixTimestamp(int64(claims["iat"].(float64))),
		sub: claims["sub"].(string),
	}
	return &infos, nil
}

func getPrivateKey() *rsa.PrivateKey {
	privateKeyFile, err := os.Open(Properties.PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	return privateKeyImported
}

func getPublicKey() *rsa.PublicKey {
	publicKeyFile, err := os.Open(Properties.PublicKeyPath)
	if err != nil {
		panic(err)
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	publicKeyFile.Close()

	publicKeyImported, err := x509.ParsePKIXPublicKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	rsaPub, ok := publicKeyImported.(*rsa.PublicKey)

	if !ok {
		panic(err)
	}

	return rsaPub
}

// fromUnixTimestamp from unix timestamp to Time
func fromUnixTimestamp(i int64) *time.Time {
	t := time.Unix(i, 0)
	return &t
}
package main

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jawher/mow.cli"
	"io/ioutil"
	"log"
	"os"
	"time"

	"crypto/rsa"
	"errors"
)

func main() {
	app := cli.App("jwt", "Stuff with jwt")

	app.Command("encode", "encode", func(cmd *cli.Cmd) {
		app.Spec = "[ea] k"
		scopes := cmd.StringsOpt("e scopes", []string{}, "desc")
		privateKeyFile := cmd.StringOpt("k key", "", "private key file")
		subject := cmd.StringOpt("a subject", "me", "subject")
		cmd.Action = func() {
			encodedToken, err := encode(*scopes, *privateKeyFile, *subject)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("encodedToken is %s\n", encodedToken)
		}
	})

	app.Command("refresh", "refresh", func(cmd *cli.Cmd) {
		//app.Spec = "k TOKEN"
		token := cmd.StringArg("TOKEN", "", "token that needs to be refreshed")
		privateKeyFile := cmd.StringOpt("k key", "~/.id_rsa", "private key file")
		cmd.Action = func() {
			refreshed, err := refresh(*token, *privateKeyFile)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("encodedToken is %s\n", refreshed)
		}
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

type CustomClaim struct {
	jwt.StandardClaims
	Scopes []string `json:"scopes"`
}

func refresh(token string, fileName string) (string, error) {
	privateKey, err := readInRsaPrivateKey(fileName)
	if err != nil {
		return "", err
	}
	publicKey := privateKey.Public()
	var claims CustomClaim
	parser := jwt.Parser{
		SkipClaimsValidation: true,
	}

	t, err := parser.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return "", errors.New("parsing err" + err.Error())
	}

	if claims, ok := t.Claims.(*CustomClaim); ok {
		claims.ExpiresAt = nowPlus10Hours()
		return newToken(*claims, privateKey)
	}
	return "", errors.New("Invalid key")
}

func nowPlus10Hours() int64 {
	_10Hours := time.Duration(10) * time.Hour
	expiresAt := time.Now().Add(_10Hours)
	return expiresAt.Unix()
}

func newToken(claim CustomClaim, privateKey *rsa.PrivateKey) (string, error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	return jwtToken.SignedString(privateKey)
}

func encode(scopes []string, fileName string, subject string) (string, error) {
	_10Hours := time.Duration(10) * time.Hour
	expiresAt := time.Now().Add(_10Hours)

	privateKey, err := readInRsaPrivateKey(fileName)
	if err != nil {
		return "", err
	}

	customClaim := CustomClaim{
		StandardClaims: jwt.StandardClaims{
			Subject:   subject,
			ExpiresAt: expiresAt.Unix(),
		},
		Scopes: scopes,
	}
	return newToken(customClaim, privateKey)
}

func readInRsaPrivateKey(fileName string) (*rsa.PrivateKey, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	pKeyData, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(pKeyData)
}

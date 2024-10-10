package main

import (
    "time"
    "github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte("your_secret_key")

// GenerateJWT now takes both username and roles as parameters
func GenerateJWT(username string, roles []string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username": username,
        "roles":    roles,  // Include roles in the JWT claims
        "exp":      time.Now().Add(time.Hour * 72).Unix(),
    })

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        return "", err
    }

    return tokenString, nil
}


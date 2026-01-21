package internal

import (
    "errors"
    "os"

    jwt "github.com/golang-jwt/jwt/v5"
)

func VerifyJWT(tokenString string) (map[string]any, error) {
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        return nil, errors.New("JWT_SECRET not set")
    }
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(secret), nil
    })
	if err != nil || !token.Valid {
        return nil, errors.New("invalid token")
    }
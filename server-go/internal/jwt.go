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
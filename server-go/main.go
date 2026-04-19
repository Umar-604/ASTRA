package main

import (
    "crypto/tls"
    "encoding/json"
    "io"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "strings"
    "time"

    "github.com/joho/godotenv"
    "server-go/internal"
)

// validateEventSchema checks minimal fields without mutating payload.
func validateEventSchema(body []byte) error {
    var v map[string]any
    if err := json.Unmarshal(body, &v); err != nil {
        return err
    }
    // agent_id required
    if a, ok := v["agent_id"].(string); !ok || strings.TrimSpace(a) == "" {
        return &json.UnmarshalTypeError{Field: "agent_id", Value: "missing_or_invalid", Type: nil}
    }
    // event_type required
    if t, ok := v["event_type"].(string); !ok || strings.TrimSpace(t) == "" {
        return &json.UnmarshalTypeError{Field: "event_type", Value: "missing_or_invalid", Type: nil}
    }
    // severity required
    if s, ok := v["severity"].(string); !ok || strings.TrimSpace(s) == "" {
        return &json.UnmarshalTypeError{Field: "severity", Value: "missing_or_invalid", Type: nil}
    }
    // data optional object
    if d, ok := v["data"]; ok && d != nil {
        if _, ok := d.(map[string]any); !ok {
            return &json.UnmarshalTypeError{Field: "data", Value: "must_be_object", Type: nil}
        }
    }
    // metadata optional object
    if m, ok := v["metadata"]; ok && m != nil {
        if _, ok := m.(map[string]any); !ok {
            return &json.UnmarshalTypeError{Field: "metadata", Value: "must_be_object", Type: nil}
        }
    }
    // timestamp optional RFC3339
    if ts, ok := v["timestamp"].(string); ok && strings.TrimSpace(ts) != "" {
        if _, err := time.Parse(time.RFC3339, ts); err != nil {
            return &json.UnmarshalTypeError{Field: "timestamp", Value: "invalid_rfc3339", Type: nil}
        }
    }
    return nil
}

func main() {
    // Load .env if present (non-fatal)
    _ = godotenv.Load()

    // Log JWT verifier configuration summary (do not print secrets)
    alg := strings.ToUpper(strings.TrimSpace(os.Getenv("JWT_ALG")))
    if alg == "" {
        alg = "HS256"
    }
    if alg == "HS256" {
        sec := os.Getenv("JWT_SECRET")
        log.Printf("jwt: alg=%s secret_len=%d", alg, len(sec))
    } else if alg == "RS256" {
        pk := os.Getenv("JWT_PUBLIC_KEY")
        pkFile := os.Getenv("JWT_PUBLIC_KEY_FILE")
        src := "none"
        if pk != "" {
            src = "env:JWT_PUBLIC_KEY"
        } else if pkFile != "" {
            src = "env:JWT_PUBLIC_KEY_FILE"
        }
        log.Printf("jwt: alg=%s public_key_source=%s", alg, src)
    } else {
        log.Printf("jwt: alg=%s (unsupported, defaulting to HS256 in verifier)", alg)
    }
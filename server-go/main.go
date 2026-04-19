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
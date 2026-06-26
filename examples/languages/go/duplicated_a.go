package main

import "strings"

func normalizeOrder(name string, email string, active bool) string {
    cleanName := strings.ToLower(strings.TrimSpace(name))
    cleanEmail := strings.ToLower(strings.TrimSpace(email))
    enabled := active && cleanEmail != ""
    if enabled {
        return cleanName + ":" + cleanEmail + ":active"
    }
    return cleanName + ":" + cleanEmail + ":inactive"
}

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

func BasicAuth(w http.ResponseWriter, r *http.Request) (success bool) {
	// Basic Auth Request
	w.Header().Set("WWW-Authenticate", `Basic realm="Check Login User"`)
	username, password, authOK := r.BasicAuth()

	if !authOK {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	// User Check
	jsonData, err := os.ReadFile(config.Users)
	if err != nil {
		PrintLog(Error, "Failed Read Users", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	var Users map[string]string // {"Name":"Pass(sha256)","Name":"Pass(sha256)",...}
	err = json.Unmarshal(jsonData, &Users)
	if err != nil {
		PrintLog(Error, "Failed Json Unmarshal Basic Auth Data", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))

	// Check Auth
	savedPass := Users[username]
	if savedPass != hash {
		w.WriteHeader(http.StatusUnauthorized)
		PrintLog(Info, fmt.Sprintf("IP:\"%s\" Login Failed:\"%s:%s\"", r.RemoteAddr, username, hash))
		return false
	}
	PrintLog(Info, fmt.Sprintf("IP:\"%s\" Login:\"%s:%s\"", r.RemoteAddr, username, hash))

	if !config.ShareDirectory {
		// Create user Dir
		userDir := filepath.Join(config.Directory, username)
		_, err = os.Stat(userDir)
		if err != nil {
			err := os.MkdirAll(userDir, 0755)
			if err != nil {
				PrintLog(Error, "Failed Create User Dir", err.Error())
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		r.URL.Path = path.Join("/", username, r.URL.Path)
	}

	return true
}

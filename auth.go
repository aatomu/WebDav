package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

func Authorization(w http.ResponseWriter, r *http.Request) (success bool) {
	// Get Username
	username := digest.GetUsername(r)
	// Get Users
	jsonData, err := os.ReadFile(config.Users)
	if err != nil {
		PrintLog(Error, "Failed Read Users", err.Error())
		digest.Require(w, lifetime)
		return false
	}
	var Users map[string]string // {"Username":"Hash","Username":"Hash",...}
	err = json.Unmarshal(jsonData, &Users)
	if err != nil {
		PrintLog(Error, "Failed Json Unmarshal Users Json", err.Error())
		digest.Require(w, lifetime)
		return false
	}

	// Check Username
	user, ok := Users[username]
	if !ok {
		digest.Require(w, lifetime)
		return false
	}
	// Check User
	ok, _ = digest.Checksum(user, r)
	if !ok {
		PrintLog(Info, fmt.Sprintf("IP:\"%s\" Login Failed:\"%s\"", r.RemoteAddr, username))
		digest.Require(w, lifetime)
		return false
	}
	PrintLog(Info, fmt.Sprintf("IP:\"%s\" Login:\"%s\"", r.RemoteAddr, username))

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

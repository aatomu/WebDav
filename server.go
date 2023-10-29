package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/net/webdav"
)

func WebDavInit() *webdav.Handler {
	return &webdav.Handler{
		FileSystem: webdav.Dir(config.Directory),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				PrintLog(Info, fmt.Sprintf("IP:\"%s\" Method:\"%s\" Path:\"%s\" Err:\"%s\"", r.RemoteAddr, r.Method, r.URL, err.Error()))
			} else {
				PrintLog(Info, fmt.Sprintf("IP:\"%s\" Method:\"%s\" Path:\"%s\"", r.RemoteAddr, r.Method, r.URL))
			}
		},
	}
}

func StartHttpsServer() {
	_, err := os.Stat(filepath.Join(config.Customize, "cert.pem"))
	if err != nil {
		PrintLog(Panic, fmt.Sprintf("HTTPS Webdav Server Boot Request File(%s): %s", filepath.Join(config.Customize, "cert.pem"), err.Error()))
		return
	}
	_, err = os.Stat(filepath.Join(config.Customize, "key.pem"))
	if err != nil {
		PrintLog(Panic, fmt.Sprintf("HTTPS Webdav Server Boot Request File(%s): %s", filepath.Join(config.Customize, "key.pem"), err.Error()))
		return
	}

	PrintLog(Info, "WebDav Server(HTTPS) Has Boot.")
	go func() {
		err := http.ListenAndServeTLS(fmt.Sprintf(":%d", config.HttpsPort), "cert.pem", "key.pem", nil)
		if err != nil {
			PrintLog(Error, "HTTPS Web Server:", err.Error())
		}
	}()
}

func StartHttpServer() {
	PrintLog(Info, "WebDav Server(HTTP) Has Boot.")
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", config.HttpPort), nil)
		if err != nil {
			PrintLog(Error, "HTTP Web Server:", err.Error())
		}
	}()
}

func RequestHandle(w http.ResponseWriter, r *http.Request) {
	// Create Save Dir
	_, err := os.Stat(config.Directory)
	if err != nil {
		err := os.MkdirAll(config.Directory, 0755)
		if err != nil {
			PrintLog(Error, "Failed Create Dir", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// Basic Auth
	if config.BasicAuth {
		success := BasicAuth(w, r)
		if !success {
			return
		}
	}

	// Browser Access(maybe)
	if r.Header.Get("Translate") != "f" && r.Header.Get("Depth") == "" {
		unknownMethod := Browser(w, r)
		if !unknownMethod {
			return
		}
	}

	// Jump Webdav
	webdavHandler.ServeHTTP(w, r)
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/net/webdav"
)

var (
	// WebDav Config
	fileDirectory = flag.String("d", "./", "File Directory")
	httpPort      = flag.Int("http", 80, "HTTP Request Port")
	httpsPort     = flag.Int("https", 443, "HTTPS Request Port")
	ssl           = flag.Bool("ssl", false, "Listen HTTPS Request")
	enableBasic   = flag.Bool("basic", false, "Enable Basic")
	// WebDav Config
	webdavHandler = &webdav.Handler{
		FileSystem: webdav.Dir(*fileDirectory),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			log.Printf("IP:%s \"%s\" %s, ERR: %v\n", r.RemoteAddr, r.Method, r.URL, err)
		},
	}
)

func main() {
	// Flag Parse and View
	flag.Parse()
	fmt.Printf("WebDav Boot Config\n")
	fmt.Printf("Directory            : %s\n", *fileDirectory)
	fmt.Printf("HTTP Port            : %d\n", *httpPort)
	fmt.Printf("HTTPS Port           : %d\n", *httpsPort)
	fmt.Printf("Secure(SSL)          : %t\n", *ssl)
	fmt.Printf("Basic Authentication : %t #HTTPSでない場合は不安定です。\n", *ssl)

	// Check Basic
	http.HandleFunc("/", HttpRequest)

	// HTTP, HTTPS server
	if *ssl {
		var isHttpsBoot = true
		_, err := os.Stat("./cert.pem")
		if err != nil {
			log.Fatalf("Failed WebDav Server Boot Prerequisite file(./cert.pem): %v", err)
			isHttpsBoot = false
		}
		_, err = os.Stat("./key.pem")
		if err != nil {
			log.Fatalf("Failed WebDav Server Boot Prerequisite file(./key.pem): %v", err)
			isHttpsBoot = false
		}

		if isHttpsBoot {
			go http.ListenAndServeTLS(fmt.Sprintf(":%d", *httpsPort), "cert.pem", "key.pem", nil)
			log.Println("HTTP WebDav Server has Boot!")
		} else {
			log.Println("Skip HTTPS WebDav Server Boot")
		}
	}
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", *httpPort), nil)
		if err != nil {
			log.Fatalf("Failed WebDav Server boot: %v", err)
		}
	}()
	log.Println("HTTP WebDav Server has Boot!")

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
}

func HttpRequest(w http.ResponseWriter, r *http.Request) {
	// Basic Auth
	if *enableBasic {
		w.Header().Set("WWW-Authenticate", `Basic realm="Check Login User"`)
		username, password, authOK := r.BasicAuth()

		if !authOK {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		log.Printf("IP:%s \"LOGIN\" %s:%s\n", r.RemoteAddr, username, password)
		if username != "aatomu" || password != "0000" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
	}

	if r.Header.Get("Depth") == "" { // Browser Check?
		if r.Method == http.MethodGet {
			info, err := webdavHandler.FileSystem.Stat(context.TODO(), r.URL.Path)
			if err == nil && info.IsDir() {
				r.Method = "PROPFIND"
			}
		}
	}

	webdavHandler.ServeHTTP(w, r)
}

func BasicAuth(w http.ResponseWriter) {

}

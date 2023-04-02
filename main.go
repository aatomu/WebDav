package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/webdav"
)

type Users struct {
	Users []User `json:"Users"`
}

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"` // SHA256で暗号化保存すること
}

type File struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Extension string `json:"extension"`
	Date      string `json:"date"`
	Size      int64  `json:"size"`
}

var (
	// WebDav Config
	fileDirectory = flag.String("dir", "./files", "File Directory")
	configs       = flag.String("config", "./config", "Config Files Directory")
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
	// おまけ
	password = flag.String("pass", "", "Password to SHA256")
)

func main() {
	// Flag Parse and View
	flag.Parse()
	if *password != "" {
		fmt.Printf("%s => %x", *password, sha256.Sum256([]byte(*password)))
		return
	}
	fmt.Printf("WebDav Boot Config\n")
	fmt.Printf("File Directory         : %s\n", *fileDirectory)
	fmt.Printf("Config Files Directory : %s\n", *configs)
	fmt.Printf("HTTP Port              : %d\n", *httpPort)
	fmt.Printf("HTTPS Port             : %d\n", *httpsPort)
	fmt.Printf("Secure(SSL)            : %t\n", *ssl)
	fmt.Printf("Basic Authentication   : %t #HTTPSでない場合は不安定です。\n", *ssl)

	// Check Basic
	if *enableBasic {
		_, err := os.Stat(filepath.Join(*configs, "users.json"))
		if err != nil {
			log.Fatalf("Failed WebDav Server Boot Prerequisite file(%s): %v", filepath.Join(*configs, "users.json"), err)
		}
	}

	// HTTP, HTTPS server
	http.HandleFunc("/", HttpRequest)
	if *ssl {
		var isHttpsBoot = true
		_, err := os.Stat(filepath.Join(*configs, "cert.pem"))
		if err != nil {
			log.Printf("Failed WebDav Server Boot Prerequisite file(%s): %v", filepath.Join(*configs, "cert.pem"), err)
			isHttpsBoot = false
		}
		_, err = os.Stat(filepath.Join(*configs, "key.pem"))
		if err != nil {
			log.Printf("Failed WebDav Server Boot Prerequisite file(%s): %v", filepath.Join(*configs, "key.pem"), err)
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
	name := "Share"
	// Basic Auth
	if *enableBasic {
		w.Header().Set("WWW-Authenticate", `Basic realm="Check Login User"`)
		username, password, authOK := r.BasicAuth()

		if !authOK || username == name {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// User List
		jsonData, err := os.ReadFile(filepath.Join(*configs, "users.json"))
		if err != nil {
			log.Printf("Failed Basic Authorized(read file): %v", err)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		var config Users
		err = json.Unmarshal(jsonData, &config)
		if err != nil {
			log.Printf("Failed Basic Authorized(json unmarshal): %v", err)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
		log.Printf("IP:%s \"LOGIN\" %s:%s\n", r.RemoteAddr, username, hash)

		// Check Auth
		var isAuthSuccess = false
		for _, user := range config.Users {
			if username == user.Name && hash == user.Password {
				isAuthSuccess = true
				break
			}
		}
		if !isAuthSuccess {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// create dir
		parent := filepath.Join(*fileDirectory, username)
		_, err = os.Stat(parent)
		if err != nil {
			err := os.Mkdir(parent, 0777)
			if err != nil {
				log.Printf("Failed Create Dir(%s): %v", parent, err)
				http.Error(w, "Failed Create User Dir", http.StatusUnauthorized)
				return
			}
		}
		name = username
	}

	if r.Header.Get("Translate") != "f" { // Browser Check?
		if r.Method == http.MethodGet {
			path := filepath.Join(*fileDirectory, name, r.URL.Path)
			// Check Request File
			requestFile, err := os.Stat(path)
			if err != nil {
				log.Printf("Failed Read Directory/File(%s): %v", filepath.Join(*configs, "template.html"), err)
				http.Error(w, "Failed Read Dir/File", http.StatusNotFound)
				return
			}

			// Read Directory
			if requestFile.IsDir() {
				files, err := os.ReadDir(path)
				if err != nil {
					log.Printf("Failed Read Directory(%s): %v", filepath.Join(*configs, "template.html"), err)
					http.Error(w, "Failed Read Dir/File", http.StatusNotFound)
					return
				}
				var directoryFiles []File
				// Root
				directoryFiles = append(directoryFiles, File{
					Name:      "/",
					Path:      "/",
					Extension: "Directory",
				})
				// Parent
				directoryFiles = append(directoryFiles, File{
					Name:      "../",
					Path:      "../",
					Extension: "Directory",
				})
				// Directory Files
				for _, f := range files {
					fileStatus, _ := os.Stat(filepath.Join(path, f.Name()))
					fileInfo := File{
						Name:      f.Name(),
						Path:      filepath.Join(r.URL.Path, f.Name()),
						Extension: filepath.Ext(f.Name()),
						Date:      fileStatus.ModTime().Format("2006/01/02-15:04:05"),
						Size:      fileStatus.Size(),
					}
					if f.IsDir() {
						fileInfo.Name += "/"
						fileInfo.Extension = "Directory"
					}
					directoryFiles = append(directoryFiles, fileInfo)
				}

				// Result File Create
				temp, err := os.ReadFile(filepath.Join(*configs, "template.html"))
				if err != nil {
					log.Printf("Failed Read File(%s): %v", filepath.Join(*configs, "template.html"), err)
					http.Error(w, "Failed Read Dir/File", http.StatusNotFound)
					return
				}
				indexFile := string(temp)
				directoryFilesBytes, _ := json.Marshal(directoryFiles)
				indexFile = strings.Replace(indexFile, "${files}", string(directoryFilesBytes), 1)
				// Return
				w.Write([]byte(indexFile))
				return
			}

			// Not Directory
			f, err := os.ReadFile(path)
			if err != nil {
				log.Printf("Failed Read File(%s): %v", filepath.Join(*configs, "template.html"), err)
				http.Error(w, "Failed Read Dir/File", http.StatusNotFound)
				return
			}
			w.Header().Add("Content-Type", "application/force-download")
			w.Header().Add("Content-Length", fmt.Sprintf("%d", len(f)))
			w.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(r.URL.Path)))
			w.WriteHeader(200)
			w.Write(f)
			return
		}
	} else {
		r.URL.Path = filepath.Join(name, r.URL.Path)
	}

	webdavHandler.ServeHTTP(w, r)
}

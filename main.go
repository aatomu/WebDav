package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/webdav"
)

type Config struct {
	Customize      string `json:"customize"`
	Users          string `json:"users"`
	Directory      string `json:"directory"`
	HttpPort       int    `json:"httpPort"`
	HttpsPort      int    `json:"httpsPort"`
	SSL            bool   `json:"ssl"`
	BasicAuth      bool   `json:"basicAuth"`
	ShareDirectory bool   `json:"shareDirectory"`
}

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"` // SHA256で暗号化保存すること
}

type FilesInfo struct {
	Auth  bool   `json:"auth"`
	Files []File `json:"files"`
}
type File struct {
	Name      string `json:"name"`
	Extension string `json:"extension"`
	Date      string `json:"date"`
	Size      int64  `json:"size"`
}

type LogLevel int

const (
	Info LogLevel = iota
	Warn
	Error
	Panic
)

var (
	// Config
	configFile = flag.String("config", "./config.json", "Config file Path")
	config     Config
	// WebDav Config
	webdavHandler *webdav.Handler
	// おまけ
	password        = flag.String("pass", "", "Password to SHA256")
	maxMemory int64 = *flag.Int64("ram", 512000000, "Post Max")
)

func main() {
	// Flag Parse and View
	flag.Parse()
	if *password != "" {
		fmt.Printf("%s => %x", *password, sha256.Sum256([]byte(*password)))
		return
	}
	// Read Config
	conf, err := os.ReadFile(*configFile)
	if err != nil {
		PrintLog(Panic, err.Error())
		return
	}
	json.Unmarshal(conf, &config)

	if config.ShareDirectory && !config.BasicAuth {
		PrintLog(Panic, "ShareDirectory Required BasicAuth")
		return
	}
	fmt.Printf("WebDav Boot Config\n")
	fmt.Printf("Config File          : %s\n", *configFile)
	fmt.Printf("Customize            : %s\n", config.Customize)
	fmt.Printf("File Directory       : %s\n", config.Directory)
	fmt.Printf("HTTP Port            : %d\n", config.HttpPort)
	fmt.Printf("HTTPS Port           : %d\n", config.HttpsPort)
	fmt.Printf("Secure(SSL)          : %t\n", config.SSL)
	fmt.Printf("Basic Authentication : %t #SSL/HTTPS Recommended.\n", config.BasicAuth)
	fmt.Printf("Share Directory      : %t #Required: BasicAuth\n", config.ShareDirectory)

	// Check Basic
	if config.BasicAuth {
		_, err := os.Stat(config.Users)
		if err != nil {
			PrintLog(Panic, "Failed Access Webdav Users File", err)
			return
		}
	}

	// Webdav Init
	webdavHandler = &webdav.Handler{
		FileSystem: webdav.Dir(config.Directory),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				PrintLog(Info, fmt.Sprintf("Webdav IP:%s \"%s\" %s ERR: %s", r.RemoteAddr, r.Method, r.URL, err.Error()))
			} else {
				PrintLog(Info, fmt.Sprintf("Webdav IP:%s \"%s\" %s", r.RemoteAddr, r.Method, r.URL))
			}
		},
	}
	// HTTP, HTTPS server
	http.HandleFunc("/", HttpRequest)
	if config.SSL {
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

		PrintLog(Info, "HTTPS Webdav Server Has Booting..")
		go func() {
			err := http.ListenAndServeTLS(fmt.Sprintf(":%d", config.HttpsPort), "cert.pem", "key.pem", nil)
			if err != nil {
				PrintLog(Error, "HTTPS Web Server:", err)
			}
		}()
	}
	log.Println("[Info]", "HTTP Webdav Server Has Booting..")
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", config.HttpPort), nil)
		if err != nil {
			PrintLog(Error, "HTTP Web Server:", err)
		}
	}()

	// Break Signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
}

func HttpRequest(w http.ResponseWriter, r *http.Request) {
	// Basic Auth
	if config.BasicAuth {
		ok := BasicAuthSuccess(w, r)
		if !ok {
			return
		}
	} else {
		_, err := os.Stat(config.Directory)
		if err != nil {
			err := os.MkdirAll(config.Directory, 0666)
			if err != nil {
				PrintLog(Error, "Failed Create Dir", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
	}

	if r.Header.Get("Translate") != "f" { // Browser Check?
		responsed := BrowserAccess(w, r)
		if responsed {
			return
		}
	}

	webdavHandler.ServeHTTP(w, r)
}

func BasicAuthSuccess(w http.ResponseWriter, r *http.Request) (responsed bool) {
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
		PrintLog(Error, "Failed Read Basic Auth Data", err)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	var Users []User
	err = json.Unmarshal(jsonData, &Users)
	if err != nil {
		PrintLog(Error, "Failed Json Unmarshal Basic Auth Data", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
	PrintLog(Info, fmt.Sprintf("IP:%s \"LOGIN\" %s:%s", r.RemoteAddr, username, hash))

	// Check Auth
	var isAuthSuccess = false
	for _, user := range Users {
		if username == user.Name && hash == user.Password {
			isAuthSuccess = true
			break
		}
	}
	if !isAuthSuccess {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !config.ShareDirectory {
		// create dir
		userDir := filepath.Join(config.Directory, username)
		_, err = os.Stat(userDir)
		if err != nil {
			err := os.MkdirAll(userDir, 0666)
			if err != nil {
				PrintLog(Error, "Failed Create User Dir", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		r.URL.Path = path.Join("/", username, r.URL.Path)
	}
	return true
}

func BrowserAccess(w http.ResponseWriter, r *http.Request) (ok bool) {
	switch r.Method {
	case http.MethodGet:
		path := filepath.Join(config.Directory, r.URL.Path)
		PrintLog(Info, fmt.Sprintf("RequestURL:\"%s\" FilePath:\"%s\"", r.URL.Path, path))
		if config.BasicAuth {
			// DownloadCheck
			passwords := r.URL.Query()["pass"]
			if len(passwords) == 1 {
				DownloadFile(w, r, path)
				return true
			}
			// Check Request File
			requestFile, err := os.Stat(path)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return true
			}

			// Read Directory
			if requestFile.IsDir() {
				ReadDirectory(w, r, path)
				return true
			}
			// Not Directory
			file, err := os.ReadFile(path)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return true
			}
			w.Write(file)
		} else {
			// DownloadCheck
			passwords := r.URL.Query()["pass"]
			if len(passwords) == 1 {
				DLfilePath := fmt.Sprintf("%s__%s", path, passwords[0])
				_, err := os.Stat(DLfilePath)
				if err != nil {
					w.WriteHeader(http.StatusNotFound)
					return true
				}

				DownloadFile(w, r, DLfilePath)
			}

			// Check Directory
			requestFile, err := os.Stat(path)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return true
			}

			// Read Directory
			if requestFile.IsDir() {
				ReadDirectory(w, r, path)
				return true
			}

			w.WriteHeader(http.StatusNotFound)
			return true
		}

	case http.MethodPost:
		r.ParseMultipartForm(maxMemory)
		formItems := r.MultipartForm.File["file"]
		for i, item := range formItems {
			src, err := item.Open()
			if err != nil {
				w.WriteHeader(http.StatusNoContent)
				continue
			}
			defer src.Close()

			saveRoot := filepath.Join(config.Directory, r.URL.Path)
			savePath := filepath.Join(saveRoot, item.Filename)
			for i := 1; true; i++ {
				_, err := os.Stat(savePath)
				if err != nil {
					break
				}
				savePath = filepath.Join(saveRoot, fmt.Sprintf("%s-%d%s", filepath.Base(item.Filename[:len(item.Filename)-len(filepath.Ext(item.Filename))]), i, filepath.Ext(item.Filename)))
			}
			if !config.BasicAuth {
				savePath = fmt.Sprintf("%s__%s", savePath, r.MultipartForm.Value["pass"][i])
			}
			dst, err := os.Create(savePath)
			if err != nil {
				PrintLog(Error, "Failed Save Upload File", err)
				w.WriteHeader(http.StatusInternalServerError)
				continue
			}
			defer dst.Close()

			io.Copy(dst, src)
			log.Println("Upload File is Saved.", savePath)
		}
		return true

	default:
		log.Println("Unknown Method?", r.Method)
		return false
	}
	return false // Dont come this line
}

func DownloadFile(w http.ResponseWriter, r *http.Request, path string) {
	acessFileInfo, err := os.Stat(path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var file []byte
	var fileName string
	if acessFileInfo.IsDir() {
		// zip buffer
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)

		// get dir items
		err = filepath.WalkDir(path, func(nowPath string, d fs.DirEntry, _ error) error {
			zipPath := strings.Replace(nowPath, path, "", 1)
			if strings.HasPrefix(zipPath, "/") {
				zipPath = strings.Replace(zipPath, "/", "", 1)
			}

			info, err := d.Info()
			if err != nil {
				return err
			}

			// CheckDir
			if d.IsDir() {
				zipWriter.Create(zipPath)
			} else {
				// Set file header
				head, err := zip.FileInfoHeader(info)
				if err != nil {
					return err
				}
				head.Name = zipPath

				// Create ziped file data
				zipdFile, err := zipWriter.CreateHeader(head)
				if err != nil {
					return err
				}

				// Set file data
				body, err := os.ReadFile(nowPath)
				if err != nil {
					return err
				}
				zipdFile.Write(body)
			}
			return nil
		})
		// Walk error
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Zip to Byte
		zipWriter.Close()
		file = buf.Bytes()
		fileName = fmt.Sprintf("%s.zip", filepath.Base(r.URL.Path))
	} else {
		file, err = os.ReadFile(path)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fileName = filepath.Base(r.URL.Path)
	}

	w.Header().Add("Content-Type", "application/force-download")
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(file)))
	w.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	w.Write(file)
}

func ReadDirectory(w http.ResponseWriter, r *http.Request, path string) {
	files, err := os.ReadDir(path)
	if err != nil {
		log.Printf("Failed Read Directory(%s): %v", path, err)
		http.Error(w, "Failed Read Dir/File", http.StatusNotFound)
		return
	}
	var filesInfo FilesInfo = FilesInfo{
		Auth:  config.BasicAuth,
		Files: []File{},
	}
	// Root
	filesInfo.Files = append(filesInfo.Files, File{
		Name:      "/",
		Extension: "Directory",
	})
	// Parent
	filesInfo.Files = append(filesInfo.Files, File{
		Name:      "../",
		Extension: "Directory",
	})
	// Directory Files
	for _, f := range files {
		fileStatus, _ := os.Stat(filepath.Join(path, f.Name()))
		fileName := f.Name()
		if !config.BasicAuth { // BasicAuthがTrueでなければpassを匿名化
			names := strings.Split(f.Name(), "__")
			fileName = strings.Join(names[:len(names)-1], "__")
		}

		fileInfo := File{
			Name:      fileName,
			Extension: filepath.Ext(fileName),
			Date:      fileStatus.ModTime().Format("2006/01/02-15:04:05"),
			Size:      fileStatus.Size(),
		}
		if f.IsDir() {
			fileInfo.Name += "/"
			fileInfo.Extension = "Directory"
		}

		filesInfo.Files = append(filesInfo.Files, fileInfo)
	}

	// Result File Create
	temp, err := os.ReadFile(filepath.Join(config.Customize, "template.html"))
	if err != nil {
		log.Printf("Failed Read File(%s): %v", filepath.Join(config.Customize, "template.html"), err)
		http.Error(w, "Failed Read Dir/File", http.StatusNotFound)
		return
	}
	indexFile := string(temp)
	FilesInfoBytes, _ := json.Marshal(filesInfo)
	indexFile = strings.Replace(indexFile, "${files}", string(FilesInfoBytes), 1)
	if config.BasicAuth {
		indexFile = strings.Replace(indexFile, "${files}", "disable", 1)
	} else {
		indexFile = strings.Replace(indexFile, "${files}", "", 1)
	}
	// Return
	w.Write([]byte(indexFile))
}

func PrintLog(level LogLevel, v ...any) {
	switch level {
	case Info:
		log.Println("[Info]", v)
	case Warn:
		log.Println("[Warn]", v)
	case Error:
		log.Println("[Error]", v)
	case Panic:
		log.Panic(v...)
	}
}

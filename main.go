package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aatomu/atomicgo/netapi"
	"golang.org/x/net/webdav"
)

type Config struct {
	Customize      string `json:"customize"`
	Users          string `json:"users"`
	Directory      string `json:"directory"`
	HttpPort       int    `json:"httpPort"`
	HttpsPort      int    `json:"httpsPort"`
	SSL            bool   `json:"ssl"`
	Authorization  bool   `json:"authorization"`
	ShareDirectory bool   `json:"shareDirectory"`
}

type FilesInfo struct {
	Auth  bool   `json:"auth"`
	Files []File `json:"files"`
}
type File struct {
	Name string `json:"name"`
	Date string `json:"date"`
	Size string `json:"size"`
}

type LogLevel int

const (
	Info LogLevel = iota
	Error
	Panic
)

var (
	// Config
	configFile = flag.String("config", "./config.json", "Config file Path")
	config     Config
	maxMemory  int64 = *flag.Int64("ram", 512000000, "Post Max")
	digest           = netapi.DigestAuthNew("Required Username,Password")
	lifetime         = 240 * time.Hour
	// WebDav Config
	webdavHandler *webdav.Handler
	// おまけ
	user     = flag.String("user", "", "Username&Password to MD5Hash")
	password = flag.String("pass", "", "Username&Password to MD5Hash")
)

func main() {
	// Flag Parse and View
	flag.Parse()
	if *user != "" && *password != "" {
		fmt.Printf("Username : %s\n", *user)
		fmt.Printf("Password : %s\n", *password)
		fmt.Printf("Hash     : %s\n", digest.NewUser(*user, *password))
		return
	}
	// Read Config
	conf, err := os.ReadFile(*configFile)
	if err != nil {
		PrintLog(Panic, err.Error())
		return
	}
	json.Unmarshal(conf, &config)

	if config.ShareDirectory && !config.Authorization {
		PrintLog(Panic, "ShareDirectory Required Authorization")
		return
	}
	fmt.Printf("====================WebDav Boot Config====================\n")
	fmt.Printf("Config File          : %s\n", *configFile)
	fmt.Printf("Customize            : %s\n", config.Customize)
	fmt.Printf("File Directory       : %s\n", config.Directory)
	fmt.Printf("HTTP Port            : %d\n", config.HttpPort)
	fmt.Printf("HTTPS Port           : %d\n", config.HttpsPort)
	fmt.Printf("Secure(SSL)          : %t\n", config.SSL)
	fmt.Printf("Basic Authentication : %t #SSL/HTTPS Required\n", config.Authorization)
	fmt.Printf("Share Directory      : %t #Required: Authorization\n", config.ShareDirectory)
	fmt.Printf("==========================================================\n")

	// Check Basic
	if config.Authorization {
		_, err := os.Stat(config.Users)
		if err != nil {
			PrintLog(Panic, "Failed Read Users", err.Error())
			return
		}
	}

	// Webdav Init
	webdavHandler = WebDavInit()

	// Set HTTP Handler
	http.HandleFunc("/", RequestHandle)
	// Boot HTTPS Server
	if config.SSL {
		StartHttpsServer()
	}
	// Boot HTTP Server
	StartHttpServer()

	// Break Signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
}

func PrintLog(level LogLevel, v ...string) {
	switch level {
	case Info:
		log.Println(strings.Join(append([]string{"[Info] : "}, v...), ""))
	case Error:
		log.Println(strings.Join(append([]string{"[Error]: "}, v...), ""))
	case Panic:
		panic(strings.Join(v, ""))
	}
}

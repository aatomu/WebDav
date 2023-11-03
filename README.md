# WebDav
簡単に動かせると思いたいWebDav Server  
HTTP HTTPS Basic認証対応  
golang: go version go1.20.1 linux/amd64  

## How To Use
Boot: `go run main.go <flags>`  
flags:
  * `-config`: webdav config json file path
  * `-user <Username> -pass <Password>`: create user data hash

### config.json
```json
{
  "customize": "<template files path>",
  "users": "<user list json file path>",
  "directory": "<use directory path>",
  "httpPort": 80,
  "httpsPort": 8080,
  "ssl": false,
  "authorization": false,
  "shareDirectory": false
}
```

### users.json
```json
{
  "<UserName>": "<Hash>",
  "<UserName>": "<Hash>",
  "<UserName>": "<Hash>",
}
```
# WebDav
簡単に動かせると思いたいWebDav Server  
HTTP HTTPS Basic認証対応  
golang: go version go1.20.1 linux/amd64  

## How To Use
Boot: `go run main.go <flags>`  
flags:
  * `-config`: webdav config json file path
  * `-password`: create plain password => sha256ed text

### config.json
```json
{
  "customize": "<template files path>",
  "users": "<user list json file path>",
  "directory": "<use directory path>",
  "httpPort": 80,
  "httpsPort": 8080,
  "ssl": false,
  "basicAuth": false,
  "shareDirectory": false
}
```

### users.json
```json
[
  {
    "Name": "<UserName>",
    "Password": "<Password(sha256)>"
  },
  {
    "Name": "<UserName>",
    "Password": "<Password(sha256)>"
  }
]
```
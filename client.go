package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func Browser(w http.ResponseWriter, r *http.Request) (unknownMethod bool) {
	switch r.Method {
	case http.MethodGet:
		path := filepath.Join(config.Directory, r.URL.Path)
		PrintLog(Info, fmt.Sprintf("Method:\"GET\" URL:\"%s\" File Path:\"%s\"", r.URL, path))

		// Download
		passwords := r.URL.Query()["pass"]
		if len(passwords) == 1 {
			// Skip Password
			if config.BasicAuth {
				DownloadFile(w, r, path)
				return
			}

			DLfilePath := fmt.Sprintf("%s__%s", path, passwords[0])
			_, err := os.Stat(DLfilePath)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			DownloadFile(w, r, DLfilePath)
			return
		}

		// Check Request File
		requestFile, err := os.Stat(path)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Read Directory
		if requestFile.IsDir() {
			ReadDirectory(w, r, path)
			return
		}

		// Open File
		if config.BasicAuth {
			file, err := os.ReadFile(path)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
			}
			w.Write(file)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		return

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
				PrintLog(Error, "Failed Save Uploaded File", err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				continue
			}
			defer dst.Close()

			io.Copy(dst, src)
			PrintLog(Info, "Upload File is Saved", savePath)
		}
	}
	return true
}

func ReadDirectory(w http.ResponseWriter, r *http.Request, path string) {
	files, err := os.ReadDir(path)
	if err != nil {
		PrintLog(Error, "Failed Read Directory", err.Error())
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var Files []File
	// Parent
	Files = append(Files, File{
		Name: "../",
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
			Name: fileName,
			Date: fileStatus.ModTime().Format("2006/01/02-15:04:05"),
			Size: FormatBytes(fileStatus.Size()),
		}
		if f.IsDir() {
			fileInfo.Name += "/"
		}

		Files = append(Files, fileInfo)
	}

	// Result File Create
	temp, err := os.ReadFile(filepath.Join(config.Customize, "template.html"))
	if err != nil {
		PrintLog(Error, "Failed Read Template HTML", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	indexFile := string(temp)
	FilesInfoBytes, _ := json.Marshal(FilesInfo{
		Auth:  config.BasicAuth,
		Files: Files,
	})
	indexFile = strings.Replace(indexFile, "${files}", string(FilesInfoBytes), 1)
	// Return
	w.Write([]byte(indexFile))
}

func DownloadFile(w http.ResponseWriter, r *http.Request, path string) {
	// File Stat
	acessFileInfo, err := os.Stat(path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Download File Data
	var file []byte
	var fileName string
	// Check Dir
	if acessFileInfo.IsDir() {
		// Zip Buffer
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)

		// Get Dir Files
		PrintLog(Info, "Start Read Dir Files to Zip")
		err = filepath.WalkDir(path, func(nowPath string, d fs.DirEntry, _ error) error {
			// Local Path => Zip Path
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
				return nil
			}

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

			return nil
		})
		PrintLog(Info, "Finish Read Dir to Zip")
		// Failed Read Dir Item
		if err != nil {
			PrintLog(Error, "Failed Read Dir Item(in ToZip)", err.Error())
			w.WriteHeader(http.StatusNotFound)
			return
		}

		PrintLog(Info, "Start Zip File to Bytes")
		// Zip to Byte
		zipWriter.Close()
		file = buf.Bytes()
		fileName = fmt.Sprintf("%s.zip", filepath.Base(r.URL.Path))
		PrintLog(Info, "Finish Zip File to Bytes")
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

func FormatBytes(value int64) (result string) {
	unit := []string{"B", "KB", "MB", "GB", "TB"}

	for i := 0; i < len(unit); i++ {
		result = fmt.Sprintf("%d %s", value, unit[i])
		if value < 1000 {
			break
		}
		value = value / 1000
	}
	return
}

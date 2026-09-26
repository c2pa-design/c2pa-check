package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func main() {
	key, url := os.Getenv("C2PA_API_KEY"), ""
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	if key == "" || url == "" {
		fmt.Fprintln(os.Stderr, "usage: C2PA_API_KEY=... go run . <url>")
		os.Exit(2)
	}

	body, _ := json.Marshal(map[string]string{"url": url})
	req, _ := http.NewRequest(http.MethodPost, "https://api.c2pa.design/v1/verifications", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var out struct {
		Result struct {
			Credential struct {
				Status string `json:"status"`
			} `json:"credential"`
			Signer struct {
				Organization string `json:"organization"`
			} `json:"signer"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(out.Result.Credential.Status, "·", out.Result.Signer.Organization)
	if out.Result.Credential.Status != "valid_trusted" {
		os.Exit(1)
	}
}

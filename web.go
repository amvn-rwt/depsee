package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed web
var webFS embed.FS

func runWebServer(addr string) {
	root, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("depsee web UI at http://127.0.0.1%s/", addr)
	log.Fatal(http.ListenAndServe(addr, http.FileServer(http.FS(root))))
}

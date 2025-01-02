// Package classification ScrAPI
//
// # This is an API-driven CTF for security researchers and students
//
//	Schemes: https
//	Version: 1
//	License: GPL-3.0 https://opensource.org/licenses/GPL-3.0
//
//	Consumes:
//	  - application/json
//
//	Produces:
//	  - application/json
//
// swagger:meta
package main

import (
	"embed"
	"log"
	"net/http"

	_ "embed"
	"scrapi/scrapi/core/functions"
	"scrapi/scrapi/core/structs"
)

//go:generate go run generate.go

//go:embed spec/swagger.yaml
var SwaggerSpec []byte

//go:embed embed
var SwaggerFS embed.FS

func main() {
	c := &functions.ScrapiImpl{Config: &functions.MonoConfig[functions.ConfigImport, functions.ConfigLocal, structs.PublicDocuments, functions.CTFTracker, functions.ConfigMiddleware]{}}
	c.Config.Local.HTTP.Host = "0.0.0.0"
	c.Config.Local.HTTP.HTTPPort = "80"
	c.Config.Local.HTTP.HTTPSPort = "443"
	c.Config.PublicDocuments.Swagger.Spec = SwaggerSpec
	c.Config.PublicDocuments.Swagger.EmbeddedFileSystem = SwaggerFS
	Router := c.Start()
	log.Println("Server at " + c.Config.Local.HTTP.HTTPSPort)
	err1 := http.ListenAndServeTLS(c.Config.Local.HTTP.Host+":"+c.Config.Local.HTTP.HTTPSPort, c.Config.Import.Config.Certificates.CertificateFile, c.Config.Import.Config.Certificates.KeyFile, Router)
	if err1 != nil {
		log.Fatal(err1)
	}
}

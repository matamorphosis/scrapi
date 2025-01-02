package functions

import (
	"io/fs"
	"net/http"
)

func ByteHandler(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Write(b)
	}
}

// Handler returns a handler that will serve a self-hosted Swagger UI with your spec embedded
func (c *ScrapiImpl) SwaggerHandler(Spec []byte) http.Handler {
	// render the index template with the proper spec name inserted
	static, _ := fs.Sub(c.Config.PublicDocuments.Swagger.EmbeddedFileSystem, "embed")
	mux := http.NewServeMux()
	mux.HandleFunc("/swagger_spec", ByteHandler(Spec))
	mux.Handle("/", http.FileServer(http.FS(static)))
	return mux
}

package handlers

import (
	"fmt"
	"net/http"
)

// HelloHandler handles the /hello route
func HelloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, VTuber project!")
}

// Fixture for recon tests. Not real code.
package main

func main() {
	r := chi.NewRouter()
	r.Get("/events", listEvents)
	api := r.Group("/api")
	api.Use(requireAuth)
	api.Post("/events/{id}/tickets", buyTicket)
	http.HandleFunc("GET /internal/stats", stats)
	dsn := os.Getenv("DATABASE_URL")
	_ = dsn
	http.ListenAndServe(":8080", r)
}

func buyTicket(w http.ResponseWriter, r *http.Request) {
	q := fmt.Sprintf("SELECT seats FROM events WHERE id = %s", chi.URLParam(r, "id"))
	_, _ = db.Query(q)
	resp, _ := http.Get(r.URL.Query().Get("callback"))
	_ = resp
}

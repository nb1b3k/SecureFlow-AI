package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

// Vulnerable: user-controlled `id` query parameter is interpolated directly
// into the SQL string via fmt.Sprintf. Classic Go SQL injection.
// CWE-89.
func getUser(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("id")
	q := fmt.Sprintf("SELECT id, email FROM users WHERE id = %s", uid)
	rows, err := db.Query(q)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var email string
		_ = rows.Scan(&id, &email)
		fmt.Fprintf(w, "%d %s\n", id, email)
	}
}

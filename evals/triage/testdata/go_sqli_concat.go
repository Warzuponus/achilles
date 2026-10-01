package cases

import (
	"database/sql"
	"net/http"
)

// lookupUser answers the user-search endpoint.
func lookupUser(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	name := r.URL.Query().Get("name")
	query := "SELECT id, email FROM users WHERE name = '" + name + "'"
	return db.Query(query)
}

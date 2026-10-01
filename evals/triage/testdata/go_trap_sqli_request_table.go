package cases

import (
	"database/sql"
	"fmt"
	"net/http"
)

// report returns the totals report for the requested table.
func report(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	reportTable := r.URL.Query().Get("table")
	query := fmt.Sprintf("SELECT month, amount FROM %s ORDER BY month", reportTable)
	return db.Query(query)
}

package cases

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

// allowedTables names the report tables totals will query. Interpolating a table
// name is unavoidable — a placeholder cannot stand in for an identifier — so the
// value is constrained to this set instead.
var allowedTables = map[string]bool{
	"monthly_totals": true,
	"daily_totals":   true,
}

// totals returns the requested totals report, oldest month first.
func totals(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	reportTable := r.URL.Query().Get("table")
	if !allowedTables[reportTable] {
		return nil, os.ErrInvalid
	}
	query := fmt.Sprintf("SELECT month, amount FROM %s ORDER BY month", reportTable)
	return db.Query(query)
}

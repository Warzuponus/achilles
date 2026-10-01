import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

// Known-vulnerable sample for the Tier-2 verification harness.
// find-sec-bugs should report SQL_INJECTION_JDBC: a non-constant string
// (concatenated user input) passed to Statement.executeQuery.
public class Vuln {
    public void query(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }
}

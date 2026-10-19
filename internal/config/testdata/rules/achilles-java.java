// Tests for configs/rules/achilles-java.yaml (opengrep --test). Never compiled.
// "ruleid: X" says the next line must be reported by rule X; "ok: X" says it must not.
package demo;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class Demo {
    private Connection conn;

    public void servletSql(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement st = conn.createStatement();
        // ruleid: achilles.java.sql-injection, achilles.java.sql-string-building
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    @GetMapping("/users")
    public void springSql(@RequestParam String id) throws Exception {
        // ruleid: achilles.java.sql-injection, achilles.java.sql-string-building
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = " + id);
        ps.executeQuery();
    }

    public void safeSql(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        // ok: achilles.java.sql-injection
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }

    public void concatenated(String table) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: achilles.java.sql-string-building
        st.execute("DROP TABLE " + table);
        // ok: achilles.java.sql-string-building
        st.execute("SELECT 1");
        String query = "SELECT * FROM user_data WHERE last_name = '" + table + "'";
        // ruleid: achilles.java.sql-string-building
        st.executeQuery(query);
        // ok: achilles.java.sql-string-building
        PreparedStatement split = conn.prepareStatement("SELECT * FROM t WHERE a = ? AND b =" + " ?");
    }

    public void command(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // ruleid: achilles.java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ok: achilles.java.command-injection
        Runtime.getRuntime().exec(new String[] {"uptime"});
    }

    public void file(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        // ruleid: achilles.java.path-traversal
        InputStream in = new FileInputStream("/srv/files/" + name);
        // ruleid: achilles.java.path-traversal
        File f = new File("/srv/files", name);
        // ok: achilles.java.path-traversal
        InputStream fixed = new FileInputStream("/srv/files/report.pdf");
    }

    public void fetch(HttpServletRequest request) throws Exception {
        // ruleid: achilles.java.ssrf
        URL u = new URL(request.getParameter("url"));
        u.openStream();
        // ok: achilles.java.ssrf
        URL fixed = new URL("https://api.example.com/items");
        // Parsing a URI, or using it as a redirect target, makes no request.
        // ok: achilles.java.ssrf
        URI parsed = new URI(request.getParameter("next"));
        // ok: achilles.java.ssrf
        URI self = URI.create(request.getRequestURL().toString());
        // ruleid: achilles.java.ssrf
        HttpRequest req = HttpRequest.newBuilder(URI.create(request.getParameter("feed"))).build();
    }

    public Object read(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: achilles.java.unsafe-deserialization
        return ois.readObject();
    }

    public void parseUnsafe() throws Exception {
        // ruleid: achilles.java.xxe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }

    public void parseSafe() throws Exception {
        // ok: achilles.java.xxe
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder();
    }

    public void crypto() throws Exception {
        // ruleid: achilles.java.weak-crypto
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        // ruleid: achilles.java.weak-crypto
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: achilles.java.weak-crypto
        Cipher plain = Cipher.getInstance("AES");
        // ok: achilles.java.weak-crypto
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        // ok: achilles.java.weak-crypto
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
    }

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        // ruleid: achilles.java.trust-all-certificates
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class AnyHost {
        // ruleid: achilles.java.trust-all-certificates
        public boolean verify(String hostname, SSLSession session) { return true; }
    }

    public void security(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        // ruleid: achilles.java.spring-csrf-disabled
        http.csrf().disable();
    }

    @GetMapping("/go")
    public ModelAndView redirect(@RequestParam("url") String url) {
        // ruleid: achilles.java.open-redirect
        return new ModelAndView("redirect:" + url);
    }

    @GetMapping("/go2")
    public void redirect2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        // ruleid: achilles.java.open-redirect
        response.sendRedirect(next);
        // ok: achilles.java.open-redirect
        response.sendRedirect("/home");
    }

    @GetMapping("/go3")
    public ResponseEntity<Void> redirect3(@RequestParam String url) {
        // ruleid: achilles.java.open-redirect
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }

    public Object xstreamLoad(String payload) {
        XStream xstream = new XStream();
        // ruleid: achilles.java.xstream-deserialization
        return xstream.fromXML(payload);
    }

    public Object xstreamSafe(String payload) {
        XStream xstream = new XStream();
        xstream.allowTypes(new Class[] {Contact.class});
        // ok: achilles.java.xstream-deserialization
        return xstream.fromXML(payload);
    }

}

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.w3c.dom.Document;
import java.io.StringReader;
import org.xml.sax.InputSource;

// Vulnerable: DocumentBuilderFactory left with default settings, which means
// external entity expansion is ENABLED. An attacker can read /etc/passwd or
// hit internal endpoints via XXE.
// CWE-611 / OWASP A05:2021 — Security Misconfiguration.
public class Vulnerable extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String body = req.getParameter("xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(body)));
        resp.getWriter().write(doc.getDocumentElement().getNodeName());
    }
}

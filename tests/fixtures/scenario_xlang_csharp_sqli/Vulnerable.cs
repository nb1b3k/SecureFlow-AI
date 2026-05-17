using System;
using System.Data.SqlClient;
using System.Web;
using System.Web.UI;

// Vulnerable: SqlCommand built from string concatenation with Request.QueryString.
// CWE-89.
public partial class UserPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        string userId = Request.QueryString["id"];
        string cs = "Server=db;Database=app;Integrated Security=true";
        using (SqlConnection conn = new SqlConnection(cs))
        {
            conn.Open();
            // Direct concat — no SqlParameter, no validation.
            string sql = "SELECT name, email FROM users WHERE id = " + userId;
            SqlCommand cmd = new SqlCommand(sql, conn);
            using (SqlDataReader r = cmd.ExecuteReader())
            {
                while (r.Read())
                {
                    Response.Write(HttpUtility.HtmlEncode(r["name"]) + "\n");
                }
            }
        }
    }
}

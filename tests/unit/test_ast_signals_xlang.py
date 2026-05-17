"""Cross-language sensitive-signal detection.

The Python-only patterns existed since v1; this test covers the additions
made for PR #2 on nb1b3k/secureflow-ai-pr-test, where Go/Java/Ruby/PHP/C#
PRs were being silently skipped by AI Discovery because
`sensitive_files_changed` was always False on them.

Each test asserts that the right signal name fires on a canonical handler
snippet for that language. If a new framework idiom is added later, this
file is where the regression test goes.
"""

from __future__ import annotations

from secureflow.analysis.ast_signals import detect


def _detect(content: str, file_path: str = "src/handler.py"):
    return detect(file_path=file_path, content=content)


def test_go_stdlib_http_handler_fires() -> None:
    code = """
package main
import "net/http"
func main() { http.HandleFunc("/user", getUser) }
"""
    r = _detect(code, "examples/xlang/app.go")
    assert r.sensitive
    assert "go_http_handler" in r.signals


def test_go_gin_router_fires() -> None:
    code = """
package main
import "github.com/gin-gonic/gin"
func main() {
    r := gin.Default()
    r.GET("/user", getUser)
    r.Run()
}
"""
    r = _detect(code, "main.go")
    assert r.sensitive
    assert "go_http_handler" in r.signals


def test_java_servlet_extends_httpservlet_fires() -> None:
    code = """
import javax.servlet.http.HttpServlet;
public class Vulnerable extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) {}
}
"""
    r = _detect(code, "Vulnerable.java")
    assert r.sensitive
    assert "spring_mapping" in r.signals  # category covers servlets too


def test_java_jaxrs_path_fires() -> None:
    code = """
import javax.ws.rs.Path;
@Path("/users")
public class UserResource { }
"""
    r = _detect(code, "UserResource.java")
    assert r.sensitive
    assert "spring_mapping" in r.signals


def test_ruby_sinatra_route_fires() -> None:
    code = """
require 'sinatra'

get '/ping' do
  params[:host]
end
"""
    r = _detect(code, "app.rb")
    assert r.sensitive
    assert "ruby_http_handler" in r.signals


def test_ruby_rails_controller_fires() -> None:
    code = """
class UsersController < ApplicationController
  before_action :authenticate
  def show
    @u = User.find(params[:id])
  end
end
"""
    r = _detect(code, "users_controller.rb")
    assert r.sensitive
    assert "ruby_http_handler" in r.signals


def test_php_request_superglobal_fires() -> None:
    code = """<?php
$id = $_GET['id'];
echo $id;
"""
    r = _detect(code, "lookup.php")
    assert r.sensitive
    assert "php_request_input" in r.signals


def test_php_laravel_route_fires() -> None:
    code = """<?php
Route::get('/user', function ($request) {
    return $request->input('name');
});
"""
    r = _detect(code, "routes/web.php")
    assert r.sensitive
    assert "php_request_input" in r.signals


def test_csharp_httpget_attribute_fires() -> None:
    code = """
using Microsoft.AspNetCore.Mvc;
[ApiController]
public class UserController : ControllerBase {
    [HttpGet("/user")]
    public IActionResult Get() => Ok();
}
"""
    r = _detect(code, "UserController.cs")
    assert r.sensitive
    assert "csharp_http_handler" in r.signals


def test_csharp_pageload_webforms_fires() -> None:
    code = """
public partial class UserPage : Page {
    protected void Page_Load(object sender, EventArgs e) { }
}
"""
    r = _detect(code, "UserPage.cs")
    assert r.sensitive
    assert "csharp_http_handler" in r.signals


def test_unrelated_python_file_does_not_fire_xlang_signals() -> None:
    """Guard against the new patterns over-firing on Python code."""
    code = """
def helper(x):
    return x * 2

class Thing:
    def run(self):
        pass
"""
    r = _detect(code, "lib/helper.py")
    new_signals = {"go_http_handler", "ruby_http_handler", "php_request_input", "csharp_http_handler"}
    assert not (new_signals & set(r.signals)), f"new signal mis-fired: {r.signals}"

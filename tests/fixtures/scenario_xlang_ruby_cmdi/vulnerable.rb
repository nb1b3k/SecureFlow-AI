require 'sinatra'

# Vulnerable: Sinatra handler runs the shell with a tainted query parameter.
# `system` with interpolation is the canonical Ruby command-injection sink.
# CWE-78 / OWASP A03:2021 — Injection.
get '/ping' do
  host = params[:host] || '127.0.0.1'
  # Shell metacharacters in `host` get executed verbatim — e.g.
  #   /ping?host=127.0.0.1;cat%20/etc/passwd
  output = `ping -c 1 #{host}`
  output
end

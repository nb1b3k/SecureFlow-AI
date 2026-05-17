import express, { Request, Response } from "express";
import { exec } from "child_process";

const app = express();

// Vulnerable: shell command interpolated with a tainted query parameter.
// `exec` runs the command through /bin/sh, so shell metacharacters in
// `host` are executed verbatim. CWE-78 / OWASP A03:2021.
app.get("/ping", (req: Request, res: Response) => {
  const host = String(req.query.host ?? "127.0.0.1");
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) {
      res.status(500).send(err.message);
      return;
    }
    res.type("text/plain").send(stdout);
  });
});

app.listen(3000);

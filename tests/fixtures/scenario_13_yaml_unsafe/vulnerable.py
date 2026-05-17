# Vulnerable: yaml.load() (the unsafe variant) on attacker-controlled
# bytes is RCE-equivalent because PyYAML can instantiate arbitrary Python
# objects via tags like `!!python/object/apply:os.system`.
# CWE-502. The safe pattern is yaml.safe_load().

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    body = request.get_data()
    # NOT yaml.safe_load — the bare yaml.load with the default Loader
    # accepts any tag, including `!!python/object/apply`.
    return {"parsed": str(yaml.load(body, Loader=yaml.Loader))}

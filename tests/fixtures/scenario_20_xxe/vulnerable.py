# Vulnerable: parsing XML with external-entity resolution enabled lets
# an attacker read local files via XXE. CWE-611.

from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse_xml():
    body = request.get_data()
    # The default lxml parser resolves external entities. The safe pattern
    # uses etree.XMLParser(resolve_entities=False, no_network=True).
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    tree = etree.fromstring(body, parser=parser)
    return {"root": tree.tag}

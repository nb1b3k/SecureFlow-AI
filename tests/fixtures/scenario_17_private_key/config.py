# Intentionally vulnerable fixture for gitleaks: a hardcoded RSA private
# key block. Real keys never belong in source. CWE-798.

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtESTk3yEXAMPLEpZmZkZG9NotARealKeyqqJ8aBcDeF9hIjKlMn
oPqRsT0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl
MnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab
CdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYzMnOp
-----END RSA PRIVATE KEY-----"""

"""Minimal sample Flask application used as a DevSecOps pipeline test target.

This is intentionally NOT production code. Dependency versions in
requirements.txt are pinned to older releases on purpose, so that the
SBOM + vulnerability mapping stages of the pipeline have real, known
CVEs to detect. Do not deploy this app or its dependencies anywhere.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "SBOM-first DevSecOps pipeline sample target (Python)."


if __name__ == "__main__":
    app.run()

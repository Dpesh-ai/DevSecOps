// Minimal sample Express application used as a DevSecOps pipeline test target.
// Dependency versions are pinned deliberately old for CVE-detection demo purposes.
const express = require("express");
const app = express();

app.get("/", (req, res) => {
  res.send("SBOM-first DevSecOps pipeline sample target (Node.js).");
});

module.exports = app;

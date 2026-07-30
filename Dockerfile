# Reproducible build/evaluation environment for the SBOM-first DevSecOps
# pipeline prototype (ToR: "Docker in order to build reproducibly").
#
# Build:  docker build -t sbom-pipeline .
# Run:    docker run --rm -v "$(pwd)/results:/app/results" sbom-pipeline
#
# Network access is required at run time (not build time) for live PyPI /
# npm registry / CISA KEV / FIRST.org EPSS lookups. When run without network
# access the pipeline still completes, using its documented offline
# fallbacks (see src/vuln_mapper.py).

FROM python:3.11-slim

# Node.js is needed for the Node.js targets (npm ci / npm audit).
# libpq-dev + build-essential are needed for the build-validation stage
# (src/build_validate.py) to succeed on targets/defectdojo-real, whose
# requirements.txt pins psycopg[c] - a native PostgreSQL client extension
# that fails to build without these system libraries present. This is a
# deliberate, evidenced example of exactly why the ToR specifies Docker for
# "reproducibility and reduc[ing] environment-related differences": running
# the same build-validation stage on a bare host without these packages
# (as documented in results/REPORT.md) fails; running it in this image
# succeeds, because the required native toolchain is part of the image
# rather than an undocumented assumption about the host machine.
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gnupg git build-essential libpq-dev && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN npm install --package-lock-only --prefix targets/node-sample && \
    npm install --package-lock-only --prefix targets/juiceshop-real && \
    npm install --package-lock-only --prefix targets/juiceshop-v9-real && \
    npm install --package-lock-only --prefix targets/express-real

ENTRYPOINT ["python3", "src/evaluate.py"]

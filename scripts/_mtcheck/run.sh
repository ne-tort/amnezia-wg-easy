#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
docker build -t mtcheck:local .
docker run --rm mtcheck:local \
  'tg://proxy?server=31.56.211.60&port=443&secret=eec379f8ddaf9d2cab33f07303882b0bae72752e6d796c6f66692e6c697665' \
  'tg://proxy?server=31.56.211.60&port=443&secret=ddc379f8ddaf9d2cab33f07303882b0bae'

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec python model/run_real_training.py

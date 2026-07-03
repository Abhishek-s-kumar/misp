#!/bin/bash
git config --system --add safe.directory /app/repository
git config --system user.email "misp-pipeline@local"
git config --system user.name "MISP Pipeline"
exec python api/server.py

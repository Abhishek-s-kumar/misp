#!/bin/bash
git config --global --add safe.directory /app/repository
git config --global user.email "misp-pipeline@local"
git config --global user.name "MISP Pipeline"
exec python api/server.py

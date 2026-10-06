"""Minimal consumer of the pinned dependencies. Benchmark fixture: never run."""
import requests
import yaml


def load(url):
    return yaml.safe_load(requests.get(url, timeout=5).text)

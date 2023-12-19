#!/usr/bin/python3

import subprocess

reqs = [
  "colorama"
]
for r in reqs:
  subprocess.call(["pip", "install", r])


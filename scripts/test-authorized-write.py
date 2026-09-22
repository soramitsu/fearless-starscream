#!/usr/bin/env python3
"""Run real package tests and reject missing or skipped qualification cases."""
import re
import subprocess
import sys

result = subprocess.run(['swift', 'test'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
sys.stdout.write(result.stdout)
if result.returncode:
    sys.exit(result.returncode)
passed = re.findall(r"^Test Case (.+) passed \(", result.stdout, re.MULTILINE)
if len(passed) != 38 or len(set(passed)) != 38:
    sys.exit('Expected exactly 38 distinct passing XCTest cases')
if re.search(r"^Test Case .+ (?:failed|skipped) \(", result.stdout, re.MULTILINE):
    sys.exit('Failed or skipped qualification case')
print('PASS: 38 distinct tests; no skipped or failed cases')

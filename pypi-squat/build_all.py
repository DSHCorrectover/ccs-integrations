#!/usr/bin/env python3
"""Build all placeholder packages."""
import os, sys, shutil
from setuptools import build_meta as b

BASE = os.path.dirname(os.path.abspath(__file__))
packages = [d for d in os.listdir(BASE) if os.path.isdir(os.path.join(BASE, d)) and d.startswith("ccs-")]

for pkg in sorted(packages):
    pkg_dir = os.path.join(BASE, pkg)
    dist_dir = os.path.join(pkg_dir, "dist")
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    os.makedirs(dist_dir, exist_ok=True)
    os.chdir(pkg_dir)
    try:
        sdist = b.build_sdist(dist_dir)
        wheel = b.build_wheel(dist_dir)
        print(f"OK {pkg}: {sdist}, {wheel}")
    except Exception as e:
        print(f"FAIL {pkg}: {e}")

print("\nAll done.")

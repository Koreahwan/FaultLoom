# Reproducible wheel verification

The package pins its build backend and runtime dependencies. Verify that a
source revision produces identical wheels by running:

```bash
SOURCE_DATE_EPOCH=946684800 \
  python3 tools/verify_reproducible_wheel.py
```

The verifier copies the package twice into independent temporary directories,
builds with dependency resolution and build isolation disabled, compares the
complete wheel bytes, prints the common SHA-256 digest, and removes its
temporary files. A mismatch exits non-zero.

`SOURCE_DATE_EPOCH` must be an integer Unix timestamp accepted by the wheel
format. The fixed value above is only a conformance value; release automation
should use a sealed source-commit timestamp. T09 remains responsible for clean
checkout CI, SBOM/provenance generation, and RC artifact retention.

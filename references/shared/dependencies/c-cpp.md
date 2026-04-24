# C and C++ Dependency Audit

## Detect

- `conanfile.py`
- `conanfile.txt`
- `vcpkg.json`
- `vcpkg-lock.json`
- `CMakeLists.txt`
- vendored `third_party/`, `vendor/`, or copied source trees

## Audit Paths

C and C++ dependency review is often dominated by vendored code and binary packages. Prefer:
- repo-configured SCA or SBOM tooling if present
- package-manager metadata review for Conan or vcpkg
- generic or external SCA when available
- manual review of vendored library versions when package metadata is absent

## What To Check

- copied third-party libraries with no clear upgrade path
- stale OpenSSL, zlib, libxml, image, archive, and HTTP libraries
- mismatch between manifest metadata and vendored source
- binary artifacts or submodules that bypass package-manager visibility

## Reporting Notes

- State clearly whether the issue came from package-manager metadata, vendored source review, or external SCA.
- Escalate uncertainty when versions cannot be mapped cleanly to advisory data.

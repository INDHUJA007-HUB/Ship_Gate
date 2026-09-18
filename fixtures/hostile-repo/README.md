# Hostile fixture manifest

The automated tests build oversized and NUL-byte binary files in a temporary
copy of this fixture. The nested tree tests depth enforcement without storing a
large or binary artifact in the source repository.


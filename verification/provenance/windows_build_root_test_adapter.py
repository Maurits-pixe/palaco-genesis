"""Isolated ORCHEASTRA build-root *test* adapter. Never import in runtime.

The fixture owns its temporary directory and provides no metadata-open operation.
A future native Windows handle-relative implementation must replace the deny gate.
This class is not an authorization primitive and does not establish containment.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from windows_metadata_name import validate_windows_metadata_basename


class BuildRootTestAdapter:
    """Create a disposable, fixture-owned root; fail closed for real reads."""

    def __init__(self):
        self._temporary = None
        self._root = None

    def __enter__(self):
        if self._temporary is not None:
            raise RuntimeError("adapter already active")
        self._temporary = TemporaryDirectory(prefix="palaco-root-test-")
        self._root = Path(self._temporary.name)
        return self

    @property
    def root(self):
        if self._root is None:
            raise RuntimeError("build-root fixture not active")
        return self._root

    def candidate_name(self, name):
        """Validate a single component without authorizing filesystem access."""
        if self._root is None:
            raise RuntimeError("build-root fixture not active")
        return validate_windows_metadata_basename(name)

    def read_metadata(self, name):
        """No native relative-handle opener exists yet: deny all reads."""
        self.candidate_name(name)
        raise PermissionError(
            "Windows trusted-root relative-handle opener NOT IMPLEMENTED; HOLD"
        )

    def __exit__(self, exc_type, exc, tb):
        temporary = self._temporary
        self._root = None
        self._temporary = None
        if temporary is not None:
            temporary.cleanup()
        return False

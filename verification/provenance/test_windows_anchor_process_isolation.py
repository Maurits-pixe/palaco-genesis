"""WNRA-05R: local subprocess isolation and resource observations; no authority."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
PYTHON_WORKER = r"""
import json, pathlib, sys, tracemalloc
sys.path.insert(0, sys.argv[1])
from windows_test_anchor_raw_bytes import FixtureByteRejected, parse_simulated_request_bytes
fixture = json.loads((pathlib.Path(sys.argv[1]) / "WNRA_05A_ANCHOR_VECTORS.json").read_text(encoding="utf-8"))
original = fixture["vectors"][0]["canonical_json"].encode("utf-8")
tracemalloc.start()
observed = []
for raw in (original, original + b"x" * (2 * 1024 * 1024)):
    try:
        parse_simulated_request_bytes(raw)
        observed.append("DENY_ONLY")
    except FixtureByteRejected as exc:
        observed.append(str(exc))
current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
print("WNRA05R_PYTHON=" + json.dumps({
    "observed": observed,
    "trace_peak_bytes": peak,
    "independent_verification": "NOT_EXECUTED",
    "authorization": "DENY",
}))
"""
NODE_WORKER = r"""
const fs = require('node:fs');
const path = require('node:path');
const {parseTestRequest} = require(path.join(process.argv[1], 'test_windows_anchor_raw_bytes_node.cjs'));
const fixture = JSON.parse(fs.readFileSync(path.join(process.argv[1], 'WNRA_05A_ANCHOR_VECTORS.json'), 'utf8'));
const original = Buffer.from(fixture.vectors[0].canonical_json, 'utf8');
const observed = [];
for (const raw of [original, Buffer.concat([original, Buffer.alloc(2 * 1024 * 1024, 0x78)])]) {
  try {
    const parsed = parseTestRequest(raw);
    observed.push(parsed.authorization === 'DENY' &&
      parsed.independent_verification === 'NOT_EXECUTED'
      ? 'DENY_ONLY' : 'UNEXPECTED_AUTHORITY');
  } catch (error) {
    observed.push(error.message);
  }
}
process.stdout.write('WNRA05R_NODE=' + JSON.stringify({
  observed,
  rss_snapshot_bytes: process.memoryUsage().rss,
  independent_verification: 'NOT_EXECUTED',
  authorization: 'DENY'
}) + '\n');
"""

class ProcessBoundaryTests(unittest.TestCase):
    def _worker(self, command, marker):
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=12,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr[-1500:])
        matches = [
            line[len(marker):]
            for line in completed.stdout.splitlines()
            if line.startswith(marker)
        ]
        self.assertEqual(len(matches), 1, msg=completed.stdout[-1000:])
        return json.loads(matches[0])

    def test_independent_worker_processes_with_observed_memory(self):
        py = self._worker(
            [sys.executable, "-c", PYTHON_WORKER, str(HERE)],
            "WNRA05R_PYTHON=",
        )
        node = self._worker(
            ["node", "-e", NODE_WORKER, str(HERE)],
            "WNRA05R_NODE=",
        )
        for result in (py, node):
            self.assertEqual(result["observed"], ["DENY_ONLY", "REQUEST_TOO_LARGE"])
            self.assertEqual(result["authorization"], "DENY")
            self.assertEqual(result["independent_verification"], "NOT_EXECUTED")
        self.assertGreater(py["trace_peak_bytes"], 0)
        self.assertGreater(node["rss_snapshot_bytes"], 0)
        # These measure DIFFERENT concepts; never compare them as an RSS ratio.
        print(
            "WNRA05R_MEMORY python_tracemalloc_peak_bytes="
            + str(py["trace_peak_bytes"])
            + " node_rss_snapshot_bytes=" + str(node["rss_snapshot_bytes"])
            + " authorization=DENY"
        )

    def test_timeout_terminates_stalled_child_without_authorization(self):
        blockers = (
            ("python", [sys.executable, "-c", "import time; time.sleep(30)"]),
            ("node", ["node", "-e", "setInterval(() => {}, 1000)"]),
        )
        for label, command in blockers:
            with self.subTest(runtime=label):
                child = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        child.communicate(timeout=0.3)
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=5)
                self.assertIsNotNone(child.returncode)
                self.assertNotEqual(child.returncode, 0)
                print("WNRA05R_TIMEOUT runtime=" + label
                      + " terminated=true authorization=DENY")


if __name__ == "__main__":
    unittest.main()

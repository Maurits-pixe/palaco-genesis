"""Windows IPC framing: strict read-only contract regressions."""
import json
import unittest

from protocol import TransferError
from windows_native_ipc_contract import (
    MAX_FRAME, WindowsInspectRequest, decode_windows_inspect_request,
    encode_windows_inspect_request,
)


class WindowsIPCContractTests(unittest.TestCase):
    def setUp(self):
        self.request = WindowsInspectRequest(b"n"*32, b"d"*32, 1, b"c"*32)
        self.frame = encode_windows_inspect_request(self.request)

    def mutate(self, **updates):
        d = json.loads(self.frame)
        d.update(updates)
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("ascii")

    def reject(self, frame):
        with self.assertRaises(TransferError):
            decode_windows_inspect_request(frame)

    def test_canonical_roundtrip(self):
        self.assertEqual(decode_windows_inspect_request(self.frame), self.request)

    def test_deterministic_encoding(self):
        self.assertEqual(encode_windows_inspect_request(self.request), self.frame)

    def test_authority_action_rejected(self):
        self.reject(self.mutate(operation="authorize"))

    def test_mutation_action_rejected(self):
        self.reject(self.mutate(operation="advance"))

    def test_unrecognized_field_rejected(self):
        self.reject(self.mutate(unlock=True))

    def test_missing_field_rejected(self):
        d = json.loads(self.frame)
        del d["challenge"]
        self.reject(json.dumps(d).encode("ascii"))

    def test_wrong_protocol_rejected(self):
        self.reject(self.mutate(protocol="PALACO-BT-WIN-IPC-V0"))

    def test_uppercase_hex_rejected(self):
        self.reject(self.mutate(namespace="A"*64))

    def test_short_hex_rejected(self):
        self.reject(self.mutate(device_binding="0"*62))

    def test_bad_generation_bool_rejected(self):
        self.reject(self.mutate(generation=True))

    def test_bad_generation_zero_rejected(self):
        self.reject(self.mutate(generation=0))

    def test_duplicate_key_rejected(self):
        self.reject(self.frame[:-1] + b',"operation":"inspect"}')

    def test_noncanonical_spacing_rejected(self):
        self.reject(json.dumps(json.loads(self.frame)).encode("ascii"))

    def test_frame_limit_rejected(self):
        self.reject(b"x"*(MAX_FRAME+1))

    def test_non_ascii_rejected(self):
        self.reject(self.frame + b"\\xff")

    def test_wrong_input_type_rejected(self):
        self.reject(self.frame.decode("ascii"))

    def test_request_type_confusion_rejected(self):
        with self.assertRaises(TransferError):
            encode_windows_inspect_request("inspect")

    def test_frame_cannot_include_credential(self):
        self.reject(self.mutate(private_key="secret"))

    def test_negative_generation_rejected(self):
        self.reject(self.mutate(generation=-1))

    def test_zero_challenge_is_parseable_not_authenticated(self):
        zero = WindowsInspectRequest(b"n"*32, b"d"*32, 1, bytes(32))
        self.assertEqual(decode_windows_inspect_request(
            encode_windows_inspect_request(zero)), zero)


if __name__ == "__main__":
    unittest.main()

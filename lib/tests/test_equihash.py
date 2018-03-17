import unittest

from lib.blockchain import serialize_header, rev_hex, uint256_from_bytes, var_int_read, bfh
from lib.equihash import validate_params, is_gbp_valid


class TestEquihash(unittest.TestCase):
    def test_params(self):
        self.assertRaises(ValueError, validate_params, 0, 1)
        self.assertRaises(ValueError, validate_params, 32, 0)

        validate_params(200, 9)
        validate_params(48, 5)

    def test_validate_solution(self):
        header = {
            'merkle_root': '136e0c24c02687053229942a731bc1cdbab3b1e476ae7b3cccc8084c96b7d27f',
            'bits': '207fffff',
            'block_height': 2525,
            'version': 1610612736,
            'timestamp': 1521329807,
            'reserved': '00000000000000000000000000000000000000000000000000000000',
            'solution': '06e7864b06746a9bd6173332bd556c55e7900db4717ad9f5df2f9b14b5d6fda9c7b2a985',
            'nonce': '00004898936ec368cb51fa3d3ee7d381f3cc62c6a2c2f74ac34842f186d70002',
            'prev_block_hash': '09e63be4b105f6ff2366d681404a7f808895d3ef88d11da1f7a4bbb09e465570'
        }

        n = 48
        k = 5

        header_bytes = bytes.fromhex(serialize_header(header, 2525))
        nonce = uint256_from_bytes(bfh(header.get('nonce'))[::-1])
        solution = bfh(header.get('solution'))[::-1]
        offset, length = var_int_read(solution, 0)
        solution = solution[offset:]

        self.assertTrue(is_gbp_valid(header_bytes, nonce, solution, n, k))

import unittest
from util import *

VER_MAIN_PUBLIC = 0x0488B21E
VER_TEST_PUBLIC = 0x043587CF
VER_LTC_MAIN_PUBLIC  = 0x019da462
VER_LTC_MAIN_PRIVATE = 0x019d9cfe
VER_LTC_TEST_PUBLIC  = 0x0436f6e1
VER_LTC_TEST_PRIVATE = 0x0436ef7d

BIP32_FLAG_KEY_PUBLIC  = 0x1
BIP32_FLAG_KEY_PRIVATE = 0x0

ADDRESS_TYPE_P2PKH       = 0x01
ADDRESS_TYPE_P2SH_P2WPKH = 0x02

ADDRESS_VERSION_P2PKH_MAINNET = 0x00
ADDRESS_VERSION_P2PKH_TESTNET = 0x6F
ADDRESS_VERSION_P2SH_MAINNET  = 0x05
ADDRESS_VERSION_P2SH_TESTNET  = 0xC4
ADDRESS_VERSION_P2PKH_LITECOIN         = 0x30
ADDRESS_VERSION_P2SH_LITECOIN          = 0x32
ADDRESS_VERSION_P2SH_LITECOIN_TESTNET  = 0x3A

NETWORK_BITCOIN_MAINNET = 0x01
NETWORK_BITCOIN_TESTNET = 0x02
NETWORK_BITCOIN_REGTEST = 0xff
NETWORK_LITECOIN        = 0x06
NETWORK_LITECOIN_TESTNET = 0x07
NETWORK_LITECOIN_REGTEST = 0x08

SCRIPTPUBKEY_P2PKH_LEN = 25
SCRIPTPUBKEY_P2SH_LEN = 23

SERIALIZED_LEN = 78  # 4 + 1 + 4 + 4 + 32 + 33

# Key data from test_address.py vector at m/0H/1 (74 bytes without version).
# depth=02, fingerprint=5C1BD648, child_num=00000001,
# chain_code=2A7857...37C19, pub_key=03501E...D711C
# pub_key_hash: bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe
KEY_DATA_NO_VER = ('025C1BD648000000012A7857'
                   '631386BA23DACAC34180DD1983734E44'
                   '4FDBF774041578E9B6ADB37C1903501E'
                   '454BF00751F24B1B489AA925215D66AF'
                   '2234E3891C3B21A52BEDB3CD711C')

# Expected scriptpubkeys for the above pub_key_hash
EXPECTED_P2PKH_SPK  = '76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac'
EXPECTED_P2SH_SPK   = 'a91486cc442a97817c245ce90ed0d31d6dbcde3841f987'
EXPECTED_WITNESS_SPK = '0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe'


class LitecoinAddressTests(unittest.TestCase):
    """Test Litecoin address encoding, decoding, and round-trips."""

    def unserialize_key(self, hex_data):
        buf, buf_len = make_cbuffer(hex_data)
        key_out = ext_key()
        ret = bip32_key_unserialize(buf, SERIALIZED_LEN, byref(key_out))
        self.assertEqual(ret, WALLY_OK)
        return key_out

    def test_litecoin_mainnet_p2pkh(self):
        """P2PKH mainnet: version 0x30 -> 'L...' address, full round-trip"""
        key_hex = '%08x' % VER_LTC_MAIN_PUBLIC + KEY_DATA_NO_VER
        key = self.unserialize_key(key_hex)

        ret, addr = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2PKH,
                                               ADDRESS_VERSION_P2PKH_LITECOIN)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addr.startswith('L'), f'Expected L... address, got {addr}')

        # address -> scriptpubkey
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2PKH_LEN)
        ret, written = wally_address_to_scriptpubkey(utf8(addr), NETWORK_LITECOIN,
                                                     out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2PKH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2PKH_SPK))

        # scriptpubkey -> address
        ret, addr2 = wally_scriptpubkey_to_address(out, written, NETWORK_LITECOIN)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr2, addr)

    def test_litecoin_mainnet_p2sh(self):
        """P2SH mainnet: version 0x32 -> 'M...' address, full round-trip"""
        key_hex = '%08x' % VER_LTC_MAIN_PUBLIC + KEY_DATA_NO_VER
        key = self.unserialize_key(key_hex)

        ret, addr = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2SH_P2WPKH,
                                               ADDRESS_VERSION_P2SH_LITECOIN)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addr.startswith('M'), f'Expected M... address, got {addr}')

        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        ret, written = wally_address_to_scriptpubkey(utf8(addr), NETWORK_LITECOIN,
                                                     out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2SH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2SH_SPK))

        ret, addr2 = wally_scriptpubkey_to_address(out, written, NETWORK_LITECOIN)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr2, addr)

    def test_litecoin_mainnet_segwit(self):
        """P2WPKH mainnet: HRP 'ltc' -> 'ltc1q...' address, full round-trip"""
        key_hex = '%08x' % VER_LTC_MAIN_PUBLIC + KEY_DATA_NO_VER
        key = self.unserialize_key(key_hex)

        ret, addr = wally_bip32_key_to_addr_segwit(key, utf8('ltc'), 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addr.startswith('ltc1q'), f'Expected ltc1q... address, got {addr}')

        # bech32 -> witness program
        out, out_len = make_cbuffer('00' * 100)
        ret, written = wally_addr_segwit_to_bytes(utf8(addr), utf8('ltc'), 0,
                                                  out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_WITNESS_SPK))

        # witness program -> bech32 (full round-trip)
        ret, addr2 = wally_addr_segwit_from_bytes(out, written, utf8('ltc'), 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr2, addr)

    def test_litecoin_testnet_p2pkh(self):
        """P2PKH testnet: version 0x6F (shared with Bitcoin testnet)"""
        key_hex = '%08x' % VER_LTC_TEST_PUBLIC + KEY_DATA_NO_VER
        key = self.unserialize_key(key_hex)

        ret, addr = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2PKH,
                                               ADDRESS_VERSION_P2PKH_TESTNET)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addr[0] in ('m', 'n'), f'Expected m/n... address, got {addr}')

        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2PKH_LEN)
        ret, written = wally_address_to_scriptpubkey(utf8(addr), NETWORK_LITECOIN_TESTNET,
                                                     out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2PKH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2PKH_SPK))

        ret, addr2 = wally_scriptpubkey_to_address(out, written, NETWORK_LITECOIN_TESTNET)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr2, addr)

    def test_litecoin_testnet_p2sh(self):
        """P2SH testnet: version 0x3A"""
        key_hex = '%08x' % VER_LTC_TEST_PUBLIC + KEY_DATA_NO_VER
        key = self.unserialize_key(key_hex)

        ret, addr = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2SH_P2WPKH,
                                               ADDRESS_VERSION_P2SH_LITECOIN_TESTNET)
        self.assertEqual(ret, WALLY_OK)

        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        ret, written = wally_address_to_scriptpubkey(utf8(addr), NETWORK_LITECOIN_TESTNET,
                                                     out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2SH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2SH_SPK))

        ret, addr2 = wally_scriptpubkey_to_address(out, written, NETWORK_LITECOIN_TESTNET)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr2, addr)

    def test_litecoin_testnet_segwit(self):
        """P2WPKH testnet: HRP 'tltc' -> 'tltc1q...' address, full round-trip"""
        key_hex = '%08x' % VER_LTC_TEST_PUBLIC + KEY_DATA_NO_VER
        key = self.unserialize_key(key_hex)

        ret, addr = wally_bip32_key_to_addr_segwit(key, utf8('tltc'), 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertTrue(addr.startswith('tltc1q'), f'Expected tltc1q... address, got {addr}')

        out, out_len = make_cbuffer('00' * 100)
        ret, written = wally_addr_segwit_to_bytes(utf8(addr), utf8('tltc'), 0,
                                                  out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_WITNESS_SPK))

        # witness program -> bech32 (full round-trip)
        ret, addr2 = wally_addr_segwit_from_bytes(out, written, utf8('tltc'), 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(addr2, addr)


class LitecoinLegacyP2SHTests(unittest.TestCase):
    """Test that legacy Litecoin P2SH addresses (0x05/0xC4 prefixes) are
    accepted when the requested network is Litecoin."""

    def test_legacy_p2sh_mainnet_as_litecoin(self):
        """A '3...' address (0x05) should parse as Litecoin when requested"""
        legacy_addr = '3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu'
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        ret, written = wally_address_to_scriptpubkey(
            utf8(legacy_addr), NETWORK_LITECOIN, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2SH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2SH_SPK))

    def test_legacy_p2sh_mainnet_as_bitcoin(self):
        """A '3...' address (0x05) should still parse as Bitcoin when requested"""
        legacy_addr = '3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu'
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        ret, written = wally_address_to_scriptpubkey(
            utf8(legacy_addr), NETWORK_BITCOIN_MAINNET, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2SH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2SH_SPK))

    def test_legacy_p2sh_testnet_as_litecoin(self):
        """A '2...' address (0xC4) should parse as Litecoin testnet when requested"""
        legacy_addr = '2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD'
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        ret, written = wally_address_to_scriptpubkey(
            utf8(legacy_addr), NETWORK_LITECOIN_TESTNET, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2SH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2SH_SPK))

    def test_legacy_p2sh_testnet_as_litecoin_regtest(self):
        """A '2...' address (0xC4) should parse as Litecoin regtest when requested"""
        legacy_addr = '2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD'
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        ret, written = wally_address_to_scriptpubkey(
            utf8(legacy_addr), NETWORK_LITECOIN_REGTEST, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2SH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2SH_SPK))

    def test_legacy_p2sh_testnet_as_bitcoin(self):
        """A '2...' address (0xC4) should still parse as Bitcoin testnet when requested"""
        legacy_addr = '2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD'
        out, out_len = make_cbuffer('00' * SCRIPTPUBKEY_P2SH_LEN)
        ret, written = wally_address_to_scriptpubkey(
            utf8(legacy_addr), NETWORK_BITCOIN_TESTNET, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(written, SCRIPTPUBKEY_P2SH_LEN)
        self.assertEqual(h(out[:written]), utf8(EXPECTED_P2SH_SPK))


class LitecoinBIP32Tests(unittest.TestCase):
    """Test BIP32 key serialization with Litecoin SLIP132 version bytes."""

    SEED = '000102030405060708090a0b0c0d0e0f'

    def test_ltc_mainnet_private_serialize_roundtrip(self):
        """Ltpv (0x019d9cfe) -> serialize -> unserialize -> verify"""
        seed, seed_len = make_cbuffer(self.SEED)
        key = ext_key()
        ret = bip32_key_from_seed(seed, seed_len, VER_LTC_MAIN_PRIVATE, 0, byref(key))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key.version, VER_LTC_MAIN_PRIVATE)

        buf, buf_len = make_cbuffer('00' * SERIALIZED_LEN)
        ret = bip32_key_serialize(key, BIP32_FLAG_KEY_PRIVATE, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)

        key2 = ext_key()
        ret = bip32_key_unserialize(buf, buf_len, byref(key2))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key2.version, VER_LTC_MAIN_PRIVATE)

    def test_ltc_mainnet_public_from_private(self):
        """Ltpv -> public -> should be Ltub (0x019da462)"""
        seed, seed_len = make_cbuffer(self.SEED)
        key = ext_key()
        ret = bip32_key_from_seed(seed, seed_len, VER_LTC_MAIN_PRIVATE, 0, byref(key))
        self.assertEqual(ret, WALLY_OK)

        buf, buf_len = make_cbuffer('00' * SERIALIZED_LEN)
        ret = bip32_key_serialize(key, BIP32_FLAG_KEY_PUBLIC, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)

        key_pub = ext_key()
        ret = bip32_key_unserialize(buf, buf_len, byref(key_pub))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key_pub.version, VER_LTC_MAIN_PUBLIC)

    def test_ltc_testnet_private_serialize_roundtrip(self):
        """ttpv (0x0436ef7d) -> serialize -> unserialize -> verify"""
        seed, seed_len = make_cbuffer(self.SEED)
        key = ext_key()
        ret = bip32_key_from_seed(seed, seed_len, VER_LTC_TEST_PRIVATE, 0, byref(key))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key.version, VER_LTC_TEST_PRIVATE)

        buf, buf_len = make_cbuffer('00' * SERIALIZED_LEN)
        ret = bip32_key_serialize(key, BIP32_FLAG_KEY_PRIVATE, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)

        key2 = ext_key()
        ret = bip32_key_unserialize(buf, buf_len, byref(key2))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key2.version, VER_LTC_TEST_PRIVATE)

    def test_ltc_testnet_public_from_private(self):
        """ttpv -> public -> should be ttub (0x0436f6e1)"""
        seed, seed_len = make_cbuffer(self.SEED)
        key = ext_key()
        ret = bip32_key_from_seed(seed, seed_len, VER_LTC_TEST_PRIVATE, 0, byref(key))
        self.assertEqual(ret, WALLY_OK)

        buf, buf_len = make_cbuffer('00' * SERIALIZED_LEN)
        ret = bip32_key_serialize(key, BIP32_FLAG_KEY_PUBLIC, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)

        key_pub = ext_key()
        ret = bip32_key_unserialize(buf, buf_len, byref(key_pub))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key_pub.version, VER_LTC_TEST_PUBLIC)

    # Expected serialized Ltub xpub at m/84'/2'/0' from seed 000102...0f.
    # Generated via: bip32_key_from_seed(seed, BTC_PRIV) -> derive path ->
    # serialize as public -> patch version to Ltub. Key material is identical
    # across Bitcoin/Litecoin (same secp256k1 curve, same HMAC-SHA512 derivation).
    EXPECTED_XPUB_84_2_0 = ('019da462033a44706f800000002ea58abe'
                            'f41356f736d62878e6d342fd9ee4234800'
                            'a0931ec89f5b1981a0ce190380ebd911e1'
                            '108b60de0cd2a6c216221700c08ce515cb'
                            '6c433f71832e3ebee52f')

    def test_ltc_child_derivation_preserves_version_and_xpub(self):
        """Derive m/84'/2'/0' and verify exact serialized xpub bytes"""
        seed, seed_len = make_cbuffer(self.SEED)
        key = ext_key()
        ret = bip32_key_from_seed(seed, seed_len, VER_LTC_MAIN_PRIVATE, 0, byref(key))
        self.assertEqual(ret, WALLY_OK)

        # Derive m/84'/2'/0'
        path = (c_uint32 * 3)(0x80000054, 0x80000002, 0x80000000)
        child = ext_key()
        ret = bip32_key_from_parent_path(key, path, 3, BIP32_FLAG_KEY_PRIVATE, byref(child))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(child.version, VER_LTC_MAIN_PRIVATE)

        # Serialize child as public and verify exact bytes
        buf, buf_len = make_cbuffer('00' * SERIALIZED_LEN)
        ret = bip32_key_serialize(child, BIP32_FLAG_KEY_PUBLIC, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)

        xpub_hex = h(buf[:buf_len])
        self.assertEqual(xpub_hex, utf8(self.EXPECTED_XPUB_84_2_0))

    def test_ltc_mainnet_public_key_roundtrip(self):
        """Ltub (0x019da462) -> serialize -> unserialize -> verify"""
        key_hex = '%08x' % VER_LTC_MAIN_PUBLIC + KEY_DATA_NO_VER
        buf, buf_len = make_cbuffer(key_hex)
        key = ext_key()
        ret = bip32_key_unserialize(buf, SERIALIZED_LEN, byref(key))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key.version, VER_LTC_MAIN_PUBLIC)

        buf2, buf2_len = make_cbuffer('00' * SERIALIZED_LEN)
        ret = bip32_key_serialize(key, BIP32_FLAG_KEY_PUBLIC, buf2, buf2_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(buf[:SERIALIZED_LEN]), h(buf2[:buf2_len]))

    def test_ltc_testnet_public_key_roundtrip(self):
        """ttub (0x0436f6e1) -> serialize -> unserialize -> verify"""
        key_hex = '%08x' % VER_LTC_TEST_PUBLIC + KEY_DATA_NO_VER
        buf, buf_len = make_cbuffer(key_hex)
        key = ext_key()
        ret = bip32_key_unserialize(buf, SERIALIZED_LEN, byref(key))
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(key.version, VER_LTC_TEST_PUBLIC)

        buf2, buf2_len = make_cbuffer('00' * SERIALIZED_LEN)
        ret = bip32_key_serialize(key, BIP32_FLAG_KEY_PUBLIC, buf2, buf2_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(buf[:SERIALIZED_LEN]), h(buf2[:buf2_len]))


if __name__ == '__main__':
    unittest.main()

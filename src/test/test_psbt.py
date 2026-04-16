import json
import unittest
from util import *

FLAG_GRIND_R = 0x4
MOD_NONE = 0
INIT_PSET = 1

with open(root_dir + 'src/data/psbt.json', 'r') as f:
    JSON = json.load(f)


class PSBTTests(unittest.TestCase):

    def parse_base64(self, src_base64, expected=WALLY_OK, flags=0):
        psbt = pointer(wally_psbt())
        ret = wally_psbt_from_base64(src_base64, flags, psbt)
        self.assertEqual(ret, expected, "{0}".format(src_base64))
        return psbt

    def to_base64(self, psbt, mod_flags=None, flags=0):
        """Dump a PSBT to base64, optionally overriding tx modifiable flags"""
        if mod_flags is not None:
            version = wally_psbt_get_version(psbt)[1]
            if version != 2:
                mod_flags = None # Ignore for v0 PSBTs
            else:
                ret, old_flags = wally_psbt_get_tx_modifiable_flags(psbt)
                self.assertEqual(ret, WALLY_OK)
                ret = wally_psbt_set_tx_modifiable_flags(psbt, mod_flags)
                self.assertEqual(ret, WALLY_OK)
        ret, base64 = wally_psbt_to_base64(psbt, flags)
        self.assertEqual(ret, WALLY_OK)
        if mod_flags is not None:
            ret = wally_psbt_set_tx_modifiable_flags(psbt, old_flags)
            self.assertEqual(ret, WALLY_OK)
        return base64

    def test_invalid(self):
        """Test deserializing invalid PSBTs"""
        for case in JSON['invalid']:
            wally_psbt_free(self.parse_base64(case['psbt'], WALLY_EINVAL))

    def test_valid(self):
        """Test deserializing and roundtripping valid PSBTs"""
        buf, buf_len = make_cbuffer('00' * 4096)
        _, is_elements_build = wally_is_elements_build()
        clone = pointer(wally_psbt())

        for case in JSON['valid']:
            is_pset = case.get('is_pset', False)
            if is_pset and not is_elements_build:
                continue # No Elements support, skip this test case

            # Cases that test workarounds for elements serialization bugs
            # don't directly round trip, as wally doesn't reproduce those bugs
            can_round_trip = case.get('can_round_trip', True)

            psbt = self.parse_base64(case['psbt'])
            self.assertEqual(wally_psbt_is_elements(psbt)[1], 1 if is_pset else 0)

            serialized = self.to_base64(psbt)
            expected = case['psbt']
            if not can_round_trip:
                # Make sure the good serialization can round-trip
                good_psbt = self.parse_base64(serialized)
                expected = self.to_base64(good_psbt)
                wally_psbt_free(good_psbt)
            self.assertEqual(serialized, expected)

            ret = wally_psbt_clone_alloc(psbt, 0, clone)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(self.to_base64(clone), serialized)
            wally_psbt_free(clone)

            ret, length = wally_psbt_get_length(psbt, 0)
            self.assertEqual(ret, WALLY_OK)

            ret, written = wally_psbt_to_bytes(psbt, 0, buf, buf_len)
            self.assertEqual((ret, written), (WALLY_OK, length))

            if not is_pset:
                version = wally_psbt_get_version(psbt)[1]
                tx = pointer(wally_tx())
                NON_FINAL = 0x1 # Don't require a finalized tx to extract
                USE_WITNESS = 0x1
                if wally_psbt_extract(psbt, NON_FINAL, tx) == WALLY_OK:
                    # Upgrade/Downgrade and make sure the same tx is extracted
                    pre_hex = wally_tx_to_hex(tx, USE_WITNESS)[1]
                    tx_version = tx.contents.version
                    new_version = 2 if version == 0 else 0
                    ret = wally_psbt_set_version(psbt, 0, new_version)
                    self.assertEqual(ret, WALLY_OK)
                    ret = wally_psbt_extract(psbt, NON_FINAL, tx)
                    self.assertEqual(ret, WALLY_OK)
                    if new_version == 2:
                        # Restore the tx version in case a v0/v1 tx was upgraded
                        tx.contents.version = tx_version
                    post_hex = wally_tx_to_hex(tx, USE_WITNESS)[1]
                    self.assertEqual(pre_hex, post_hex)

            wally_psbt_free(psbt)

    def test_creator_role(self):
        """Test the PSBT creator role"""
        psbt = pointer(wally_psbt())

        for case in JSON['creator']:
            self.assertEqual(WALLY_OK, wally_psbt_init_alloc(case['version'], 2, 3, 0, 0, psbt))

            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))

            for i, txin in enumerate(case['inputs']):
                tx_in = pointer(wally_tx_input())
                txid, txid_len = make_cbuffer(txin['txid'])
                ret = wally_tx_input_init_alloc(txid[::-1], txid_len, txin['vout'], 0xffffffff, None, 0, None, tx_in)
                self.assertEqual(WALLY_OK, ret)

                if (case['version'] == 0):
                    self.assertEqual(WALLY_OK, wally_tx_add_input(tx, tx_in))
                else:
                    self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, i, 0, tx_in))

            for i, txout in enumerate(case['outputs']):
                address, satoshi = txout['address'], txout['satoshi']
                spk, spk_len = make_cbuffer('00' * (32 + 2))
                ret, written = wally_addr_segwit_to_bytes(address, 'bcrt', 0, spk, spk_len)
                self.assertEqual(WALLY_OK, ret)
                output = pointer(wally_tx_output())
                self.assertEqual(WALLY_OK, wally_tx_output_init_alloc(satoshi, spk, written, output))
                if (case['version'] == 0):
                    self.assertEqual(WALLY_OK, wally_tx_add_output(tx, output))
                else:
                    self.assertEqual(WALLY_OK, wally_psbt_add_tx_output_at(psbt, i, 0, output))

            if (case['version'] == 0):
                self.assertEqual(WALLY_OK, wally_psbt_set_global_tx(psbt, tx))

            self.assertEqual(self.to_base64(psbt, MOD_NONE), case['result'])
            wally_psbt_free(psbt)

    def test_combiner_role(self):
        """Test the PSBT combiner role"""
        for case in JSON['combiner']:
            psbt = self.parse_base64(case['psbts'][0])
            for src_b64 in case['psbts'][1:]:
                src = self.parse_base64(src_b64)
                self.assertEqual(WALLY_OK, wally_psbt_combine(psbt, src))
                wally_psbt_free(src)
            self.assertEqual(self.to_base64(psbt), case['result'])
            wally_psbt_free(psbt)

        # Invalid cases
        psbt = self.parse_base64(JSON['combiner'][0]['psbts'][0])
        src = self.parse_base64(JSON['combiner'][0]['psbts'][1])
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine(None, src))        # Null dest
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine(psbt, None))       # Null src
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(None, 0, src))  # Null dest
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(psbt, 4, src))  # Unknown flags
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(psbt, 0, None)) # Null src
        self.assertEqual(WALLY_EINVAL, wally_psbt_combine_ex(psbt, 1, src))  # Non-sig-only src

    def roundtrip(self, psbt, expected=None):
        b64_out = self.to_base64(psbt)
        if expected:
            self.maxDiff = None
            self.assertEqual(b64_out, expected)
        wally_psbt_free(psbt)
        psbt = self.parse_base64(b64_out)
        self.assertEqual(b64_out, self.to_base64(psbt))
        wally_psbt_free(psbt)
        return b64_out

    def check_signature_only_psbt(self, unsigned_b64, signed_b64):
        FLAG_SIGS_ONLY = 0x2 # WALLY_PSBT_SERIALIZE_SIGS_ONLY
        FLAG_LOOSE = 0x2 # WALLY_PSBT_PARSE_FLAG_LOOSE
        FLAG_COMBINE_SIGS = 0x1 # WALLY_PSBT_COMBINE_SIGS

        # Convert the signed PSBT into a signature-only PSBT
        signed = self.parse_base64(signed_b64)
        sigs_only_b64 = self.to_base64(signed, flags=FLAG_SIGS_ONLY)
        sigs_only = self.parse_base64(sigs_only_b64, flags=FLAG_LOOSE)
        # Combine the sigs-only PSBT with the unsigned PSBT
        unsigned = self.parse_base64(unsigned_b64)
        ret = wally_psbt_combine_ex(unsigned, FLAG_COMBINE_SIGS, sigs_only)
        # Ensure the resulting combined PSBT matches the signed psbt
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(self.to_base64(unsigned), signed_b64)

    def do_sign(self, case):
        expected = case.get('result', None)
        expected_ret = WALLY_OK if expected else WALLY_EINVAL
        priv_key, priv_key_len = make_cbuffer('00'*32)
        psbt = self.parse_base64(case['psbt'])
        wally_psbt_signing_cache_enable(psbt, 0) # Enable signing cache
        for wif in case['privkeys']:
            self.assertEqual(WALLY_OK, wally_wif_to_bytes(wif, 0xEF, 0, priv_key, priv_key_len))
            self.assertEqual(expected_ret, wally_psbt_sign(psbt, priv_key, priv_key_len, FLAG_GRIND_R))
        # Check that we can roundtrip the signed PSBT (some bugs only appear here)
        b64_out = self.roundtrip(psbt, expected)
        self.check_signature_only_psbt(case['psbt'], b64_out)

        if expected and case.get('master_xpriv', None):
            # Test signing with the master extended private key.
            # Note we cannot check for equality with the explicit private keys
            # in all cases, since the PSBTs contain multiple keys from the same
            # master, and some test cases only give a subset as explicit private keys.
            key_out = POINTER(ext_key)()
            ret = bip32_key_from_base58_alloc(case['master_xpriv'], byref(key_out))
            self.assertEqual(ret, WALLY_OK)
            psbt = self.parse_base64(case['psbt'])
            wally_psbt_signing_cache_enable(psbt, 0) # Enable signing cache
            ret = wally_psbt_sign_bip32(psbt, key_out, 0x4)
            # If all of the explicit private keys resulting from the master xpriv
            # are present, we can verify the fully signed result matches exactly
            can_match = case.get('all_privkeys_present', False)
            b64_out = self.roundtrip(psbt, expected if can_match else None)
            if not can_match:
                # Check that the result changed at least, i.e. some inputs were signed
                self.assertNotEqual(b64_out, case['psbt'])
            self.check_signature_only_psbt(case['psbt'], b64_out)
            bip32_key_free(key_out)

    def test_signer_role(self):
        """Test the PSBT signer role"""
        _, is_elements_build = wally_is_elements_build()

        for case in JSON['signer']:
            if is_elements_build or not case.get('is_pset', False):
                self.do_sign(case)

        for case in JSON['invalid_signer']:
            if is_elements_build or not case.get('is_pset', False):
                self.do_sign(case)

    def test_finalizer_role(self):
        """Test the PSBT finalizer role"""
        _, is_elements_build = wally_is_elements_build()
        SERIALIZE_FLAG_REDUNDANT = 0x1
        for case in JSON['finalizer']:
            is_pset = case.get('is_pset', False)
            expected_ret = WALLY_EINVAL if is_pset and not is_elements_build else WALLY_OK
            psbt = self.parse_base64(case['psbt'], expected_ret)
            flags = case['flags']
            ret = wally_psbt_finalize(psbt, flags)
            self.assertEqual(ret, expected_ret);
            if expected_ret == WALLY_OK:
                ret, is_finalized = wally_psbt_is_finalized(psbt)
                self.assertEqual((ret, is_finalized), (WALLY_OK, 1))
                extract_flags = SERIALIZE_FLAG_REDUNDANT if flags == 1 else 0
                self.assertEqual(self.to_base64(psbt, flags=extract_flags), case['result'])
                wally_psbt_free(psbt)

    def test_extractor_role(self):
        """Test the PSBT extractor role"""
        _, is_elements_build = wally_is_elements_build()

        for case in JSON['extractor']:
            if case.get('is_pset', False) and not is_elements_build:
                continue # No Elements support, skip this test case

            psbt = self.parse_base64(case['psbt'])
            tx = pointer(wally_tx())
            self.assertEqual(WALLY_OK, wally_psbt_extract(psbt, 0, tx))
            ret, tx_hex = wally_tx_to_hex(tx, 1)
            self.assertEqual((ret, tx_hex), (WALLY_OK, case['result']))
            wally_tx_free(tx)
            wally_psbt_free(psbt)

    def test_v20dot1_changes(self):
        """See https://github.com/ElementsProject/libwally-core/issues/213
           Verify that core v20.1 changes to address the segwit fee attack now work"""
        b64 = 'cHNidP8BAJoCAAAAAvezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAQAAAAD9////krlOMdd9VVzPWn5+oadTb4C3NnUFWA3tF6cb1RiI4JAAAAAAAP3///8CESYAAAAAAAAWABQn/PFABd2EW5RsCUvJitAYNshf9BAnAAAAAAAAFgAUFpodxCngMIyYnbJ1mhpDwQykN4cAAAAAAAEAiQIAAAABfRJscM0GWu793LYoAX15Mnj+dVr0G7yvRMBeWSmvPpQAAAAAFxYAFESkW2FnrJlkwmQZjTXL1IVM95lW/f///wK76QAAAAAAABYAFB33sq8WtoOlpvUpCvoWbxJJl5rhECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcAAAAAAQEgECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcBBBYAFIsieXd6AAeP8TXHKZ329Z0nuSeZIgYD/ajyzV90ghQ+0zIO2mVSd3fGYhvwYjakGCY4WNYxoeYEiyJ5dwABAHICAAAAAfezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAAAAAAD9////AhAnAAAAAAAAF6kUXJfUn/nNbND+a+QhqHnyCSy9oPmHHcIAAAAAAAAWABSUD3a8pIYaaLvKdZxoEPFfo8vlDwAAAAABASAQJwAAAAAAABepFFyX1J/5zWzQ/mvkIah58gksvaD5hwEEFgAUyRIBhZwlI4RLT6NDHluovlrN3iAiBgIs+YA2N8B5O6nF4SgVEG765xfHZFKrLiKbjZuo8/9vPATJEgGFACICAq8h+ABETC5Tczuts3xhCtXAzIEUHM5iMugvwFMrtCc4EBK06cYAAACAAQAAgMMAAIAAAA=='
        psbt = self.parse_base64(b64)
        buf, buf_len = make_cbuffer('00'*32)
        for priv in ['cTatuMdjH4YA4F1pAm11QdbCt88T8t2TTMoAvVGzAxWAWmQZtkBZ',
                     'cR5yyo2g1SzzwCw2QAREzF7XhYuXZS9SzTTf8A9qerri9EXZcRYS']:
            self.assertEqual(wally_wif_to_bytes(priv, 0xEF, 0, buf, buf_len), WALLY_OK)
            self.assertEqual(wally_psbt_sign(psbt, buf, buf_len, FLAG_GRIND_R), WALLY_OK)
        self.assertEqual(wally_psbt_finalize(psbt, 0), WALLY_OK)

        expected = 'cHNidP8BAJoCAAAAAvezqpNxOIDkwNFhfZVLYvuhQxqmqNPJwlyXbhc8cuLPAQAAAAD9////krlOMdd9VVzPWn5+oadTb4C3NnUFWA3tF6cb1RiI4JAAAAAAAP3///8CESYAAAAAAAAWABQn/PFABd2EW5RsCUvJitAYNshf9BAnAAAAAAAAFgAUFpodxCngMIyYnbJ1mhpDwQykN4cAAAAAAAEAiQIAAAABfRJscM0GWu793LYoAX15Mnj+dVr0G7yvRMBeWSmvPpQAAAAAFxYAFESkW2FnrJlkwmQZjTXL1IVM95lW/f///wK76QAAAAAAABYAFB33sq8WtoOlpvUpCvoWbxJJl5rhECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcAAAAAAQEgECcAAAAAAAAXqRTFhAlcZBMRkG4iAustDT6iSw6wkIcBBxcWABSLInl3egAHj/E1xymd9vWdJ7knmQEIawJHMEQCIAkPXe9sdpRjSDTjJ0gIrpwGGIWJby9xSd1rS9hPe1f0AiAJgqR7PL3G/MXyUu4KZdS1Z2O14fjxstF43k634u+4GAEhA/2o8s1fdIIUPtMyDtplUnd3xmIb8GI2pBgmOFjWMaHmAAEAcgIAAAAB97Oqk3E4gOTA0WF9lUti+6FDGqao08nCXJduFzxy4s8AAAAAAP3///8CECcAAAAAAAAXqRRcl9Sf+c1s0P5r5CGoefIJLL2g+YcdwgAAAAAAABYAFJQPdrykhhpou8p1nGgQ8V+jy+UPAAAAAAEBIBAnAAAAAAAAF6kUXJfUn/nNbND+a+QhqHnyCSy9oPmHAQcXFgAUyRIBhZwlI4RLT6NDHluovlrN3iABCGsCRzBEAiAOzRsNZ+2Et+VGCY/nXWO7WxGI3u39kpi025cUaJXQJgIgL6KtMqPfAwXGktQFWr9SNnOrHF2xjvKQI2VdeuQbxt0BIQIs+YA2N8B5O6nF4SgVEG765xfHZFKrLiKbjZuo8/9vPAAiAgKvIfgAREwuU3M7rbN8YQrVwMyBFBzOYjLoL8BTK7QnOBAStOnGAAAAgAEAAIDDAACAAAA='
        self.assertEqual(self.to_base64(psbt), expected)

    def test_psbt(self):
        """Test creating and modifying various PSBT fields"""
        tx = pointer(wally_tx())
        self.assertEqual(WALLY_OK, wally_tx_init_alloc(2, 0, 2, 2, tx))

        psbt = pointer(wally_psbt())
        for ver, result in [
            (0, 'cHNidP8A'),
            (1, None),
            (2, 'cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA=='),
            (3, None) ]:
            ret = wally_psbt_init_alloc(ver, 0, 0, 0, 0, psbt)
            self.assertEqual(ret, WALLY_OK if result else WALLY_EINVAL)
            if result:
                self.assertEqual(self.to_base64(psbt, MOD_NONE), result)

                # Global tx can only be set on a version 0 PSBT
                ret = wally_psbt_set_global_tx(psbt, tx)
                self.assertEqual(ret, WALLY_OK if ver == 0 else WALLY_EINVAL)

        # Create a v2 PSBT
        wally_psbt_init_alloc(2, 0, 0, 0, 0, psbt)

        self.assertEqual(wally_psbt_set_tx_version(psbt, 123), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8BAgR7AAAAAQQBAAEFAQAB+wQCAAAAAA==')

        self.assertEqual(wally_psbt_set_fallback_locktime(psbt, 456), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8BAgR7AAAAAQMEyAEAAAEEAQABBQEAAfsEAgAAAAA=')

        self.assertEqual(wally_psbt_clear_fallback_locktime(psbt), WALLY_OK)
        self.assertEqual(self.to_base64(psbt, MOD_NONE), 'cHNidP8BAgR7AAAAAQQBAAEFAQAB+wQCAAAAAA==')

        self.assertEqual(wally_psbt_set_tx_modifiable_flags(psbt, 3), WALLY_OK)
        self.assertEqual(self.to_base64(psbt), 'cHNidP8BAgR7AAAAAQQBAAEFAQABBgEDAfsEAgAAAAA=')

        # Create an input
        tx_input = pointer(wally_tx_input())

        txhash, txhash_len = make_cbuffer('e7f25add4560021c77c4944f92739025fddbf99816d79c06d219268ca9f4b7e7')
        ret = wally_tx_input_init_alloc(txhash, txhash_len, 5, 6, b'\x59', 1, None, tx_input)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_tx_input_at(psbt, 0, 0, tx_input)
        self.assertEqual(WALLY_OK, ret)
        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8BAgR7AAAAAQQBAQEFAQABBgEDAfsEAgAAAAABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAAA==', base64)

        ret = wally_psbt_input_set_required_lockheight(psbt.contents.inputs[0], 499999999)
        self.assertEqual(WALLY_OK, ret)
        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8BAgR7AAAAAQQBAQEFAQABBgEDAfsEAgAAAAABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAARIE/2TNHQA=', base64)

        tx_output = pointer(wally_tx_output())

        wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_output)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output)
        self.assertEqual(WALLY_OK, ret)

        ret, base64 = wally_psbt_to_base64(psbt, 0)
        self.assertEqual(WALLY_OK, ret)
        self.assertEqual('cHNidP8BAgR7AAAAAQQBAQEFAQEBBgEDAfsEAgAAAAABDiDn8lrdRWACHHfElE+Sc5Al/dv5mBbXnAbSGSaMqfS35wEPBAUAAAABEAQGAAAAARIE/2TNHQABAwjSBAAAAAAAAAEEAllZAA==', base64)

    def test_invalid_args(self):
        """Test invalid arguments to various PSBT functions"""
        psbt = pointer(wally_psbt())

        # init
        cases = [
            (1, 0, 0, 0, 0, psbt), # Invalid version
            (0, 0, 0, 0, 0xff, psbt), # Invalid flags
            (2, 0, 0, 0, 0xff, psbt), # Invalid flags (v2)
            (0, 0, 0, 0, INIT_PSET, psbt), # v0 PSET
            (0, 0, 0, 0, 0, None), # NULL dest
        ]
        for args in cases:
            self.assertEqual(WALLY_EINVAL, wally_psbt_init_alloc(*args))

        # psbt_from_base64
        src_base64 = JSON['valid'][0]['psbt']
        src_len = len(src_base64)
        for args in [(None,       0,    psbt),  # NULL base64
                     ('',         0,    psbt),  # Empty base64
                     (src_base64, 0xff, psbt),  # Invalid flags
                     (src_base64, 0,    None)]: # NULL dest
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64(*args))

        for args in [(None,       src_len, 0, psbt),   # NULL base64 string, non-0 length
                     (src_base64, 0,       0, psbt)]:  # Non-NULL base64 string, 0 length
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64_n(*args))

        self.assertEqual(WALLY_OK, wally_psbt_from_base64(src_base64, 0, psbt))
        self.assertEqual(WALLY_OK, wally_psbt_from_base64_n(src_base64, src_len, 0, psbt))

        # psbt_clone_alloc
        clone = pointer(wally_psbt())
        for args in [(None, 0x0, clone), # NULL src
                     (psbt, 0x1, clone), # Invalid flags
                     (psbt, 0x0, None)]: # NULL dest
            self.assertEqual(WALLY_EINVAL, wally_psbt_clone_alloc(*args))

        # Populate PSBT with one input and output to test various invalid args for taproot keypaths
        self.assertEqual(WALLY_OK, wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt))
        tx_in = pointer(wally_tx_input())
        self.assertEqual(WALLY_OK, wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in))

        tx_output = pointer(wally_tx_output())
        ret = wally_tx_output_init_alloc(1234, b'\x59\x59', 2, tx_output)
        self.assertEqual(WALLY_OK, ret)
        ret = wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output)
        self.assertEqual(WALLY_OK, ret)

        pk, pk_len = make_cbuffer('339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0')
        mkl, mkl_len = make_cbuffer('00' * 32)
        fpr, fpr_len = make_cbuffer('00' * 4)
        path, path_len = (c_uint32 * 1)(), 1
        i, flags = 0, 0

        invalid_args = [
            (None, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # NULL psbt
            (psbt, 1, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # Invalid index
            (psbt, i, 0x01,  pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # Invalid flags
            (psbt, i, flags, pk,   pk_len+1, mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # Bad pubkey length
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len-1, fpr, fpr_len,   path, path_len),   # Bad tapleaf_hashes_len
            (psbt, i, flags, pk,   pk_len,   None,  mkl_len,   fpr, fpr_len,   path, path_len),   # Merkle length should be 0
            (psbt, i, flags, None, pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len),   # No pubkey given
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len-1, path, path_len),   # Bad fpr length
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   None, path_len),   # NULL child path
            (psbt, i, flags, pk,   pk_len,   mkl,   mkl_len,   fpr, fpr_len,   path, path_len-1), # Bad child path length
        ]

        for args in invalid_args:
            self.assertEqual(WALLY_EINVAL, wally_psbt_add_input_taproot_keypath(*args))
            self.assertEqual(WALLY_EINVAL, wally_psbt_add_output_taproot_keypath(*args))

        valid_args = (psbt, i, flags, pk, pk_len, mkl, mkl_len, fpr, fpr_len, path, path_len)
        self.assertEqual(WALLY_OK, wally_psbt_add_input_taproot_keypath(*valid_args))
        self.assertEqual(WALLY_OK, wally_psbt_add_output_taproot_keypath(*valid_args))

    def test_redundant(self):
        """Test serializing redundant finalized input information"""
        buf, buf_len = make_cbuffer('00' * 4096)
        b64 = 'cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA'
        psbt = self.parse_base64(b64)
        # Set a fake redeem script to the finalized input 0
        redeem, redeem_len = make_cbuffer('00' * 64)
        ret = wally_psbt_input_set_redeem_script(psbt.contents.inputs[0], redeem, redeem_len)
        self.assertEqual(ret, WALLY_OK)
        # This round trips by default, i.e. it doesn't include the redeem
        # script since the input is finalized
        serialized = self.to_base64(psbt)
        self.assertEqual(serialized, b64)
        # When SERIALIZE_FLAG_REDUNDANT is given, the redeem script is included
        SERIALIZE_FLAG_REDUNDANT = 0x1
        serialized = self.to_base64(psbt, None, SERIALIZE_FLAG_REDUNDANT)
        self.assertNotEqual(serialized, b64)

SCALAR_LEN = 32
SENDER_KEY = bytes([0xa1] * SCALAR_LEN)
STEALTH_KEY = bytes([0xb2] * SCALAR_LEN)
OUT_JADE_KEY = bytes([0xfc, 0x04]) + b'JADE' + bytes([0x01])
KRN_JADE_KEY = bytes([0xfc, 0x04]) + b'JADE' + bytes([0x02])
MWEB_INPUT_AMOUNT = 500000000
MWEB_INPUT_OUTPUT_ID = bytes([0xc1] * 32)
MWEB_OUT_STEALTH_ADDR = bytes([0xd2] * 66)   # 33 scan pubkey || 33 spend pubkey
MWEB_OUT_COMMIT = bytes([0xd3] * 33)


def _varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return bytes([0xfd]) + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return bytes([0xfe]) + n.to_bytes(4, 'little')
    return bytes([0xff]) + n.to_bytes(8, 'little')


def _varbuff(data):
    return _varint(len(data)) + bytes(data)


def _build_psbt_with_mweb_kernel(sender_key=SENDER_KEY, stealth_key=STEALTH_KEY,
                                 output_amount=123456789,
                                 mweb_input=True, mweb_output=True,
                                 include_input_amount=True):
    """Build a PSBTv2 whose shape exercises the strip helper's full contract:
    one MWEB input (carrying MWEB_IN_SPENT_OUTPUT_ID and optionally
    MWEB_IN_INPUT_AMOUNT), one output (MWEB-shaped by default: stealth
    address + commit), and one MWEB kernel carrying the JADE presign field.

    Flags:
      - sender_key/stealth_key: None to omit the JADE presign field.
      - mweb_input=False: build a 0-input PSBT (still has MWEB kernel).
      - mweb_output=False: fall back to a standard output with 1-byte
        script (keeps the fixture small for the output-helper tests).
      - include_input_amount=False: omit MWEB_IN_INPUT_AMOUNT (0x97) on
        the input. Only meaningful when mweb_input=True."""
    magic = b'psbt\xff'
    num_inputs = 1 if mweb_input else 0

    # Globals
    globals_bytes = (
        _varbuff(bytes([0xfb])) + _varbuff((2).to_bytes(4, 'little'))         # PSBT_GLOBAL_VERSION = 2
      + _varbuff(bytes([0x02])) + _varbuff((2).to_bytes(4, 'little'))         # PSBT_GLOBAL_TX_VERSION = 2
      + _varbuff(bytes([0x04])) + _varbuff(bytes([num_inputs]))               # PSBT_GLOBAL_INPUT_COUNT
      + _varbuff(bytes([0x05])) + _varbuff(bytes([0x01]))                     # PSBT_GLOBAL_OUTPUT_COUNT = 1
      + _varbuff(bytes([0x92])) + _varbuff(bytes([0x01]))                     # MWEB_GLOBAL_KERNEL_COUNT = 1
      + bytes([0x00])                                                         # separator
    )

    # Input 0 (optional). MWEB_IN_SPENT_OUTPUT_ID (0x90) marks the input
    # canonical MWEB so the parser drops the v2 txid/vout requirements.
    input_bytes = b''
    if mweb_input:
        input_bytes += _varbuff(bytes([0x90])) + _varbuff(MWEB_INPUT_OUTPUT_ID)
        if include_input_amount:
            input_bytes += (_varbuff(bytes([0x97]))
                          + _varbuff(MWEB_INPUT_AMOUNT.to_bytes(8, 'little')))
        input_bytes += bytes([0x00])  # separator

    # Output 0. MWEB-shaped by default (stealth address 0x90 + commit 0x91).
    output_bytes = (
        _varbuff(bytes([0x03])) + _varbuff(output_amount.to_bytes(8, 'little'))  # PSBT_OUT_AMOUNT
    )
    if mweb_output:
        output_bytes += _varbuff(bytes([0x90])) + _varbuff(MWEB_OUT_STEALTH_ADDR)
        output_bytes += _varbuff(bytes([0x91])) + _varbuff(MWEB_OUT_COMMIT)
    else:
        output_bytes += _varbuff(bytes([0x04])) + _varbuff(bytes([0x51]))        # OP_1 script
    if sender_key is not None:
        output_bytes += _varbuff(OUT_JADE_KEY) + _varbuff(sender_key)
    output_bytes += bytes([0x00])  # separator

    # Kernel 0
    kernel_bytes = b''
    if stealth_key is not None:
        kernel_bytes += _varbuff(KRN_JADE_KEY) + _varbuff(stealth_key)
    kernel_bytes += bytes([0x00])  # separator

    return magic + globals_bytes + input_bytes + output_bytes + kernel_bytes


class MWEBPresignTests(unittest.TestCase):
    """Commit 1: libwally presign proprietary-key helpers.

    Covers round-trip, length validation, setter/getter symmetry, and the
    strip helper's exact scope (clears 0xFC "JADE" 0x01 / 0x02 plus the
    input MWEB_IN_INPUT_AMOUNT field, preserves everything else)."""

    def parse_bytes(self, data):
        psbt = pointer(wally_psbt())
        ret = wally_psbt_from_bytes(data, len(data), 0, psbt)
        self.assertEqual(ret, WALLY_OK)
        return psbt

    def serialize(self, psbt):
        buf, buf_len = make_cbuffer('00' * 4096)
        ret, written = wally_psbt_to_bytes(psbt, 0, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)
        return bytes(buf[:written])

    def test_output_senderkey_roundtrip(self):
        raw = _build_psbt_with_mweb_kernel()
        psbt = self.parse_bytes(raw)
        try:
            # Serialise, re-parse, serialise again: the second serialisation
            # is byte-identical (idempotency), and the JADE proprietary key
            # is present in the wire output.
            first = self.serialize(psbt)
            self.assertIn(b'JADE', first)
            psbt2 = self.parse_bytes(first)
            try:
                self.assertEqual(self.serialize(psbt2), first)
            finally:
                wally_psbt_free(psbt2)

            # Getter returns the value we put in.
            out = psbt.contents.outputs[0]
            buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, written = wally_psbt_output_get_mweb_presign_sender_key(out, buf, buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, SCALAR_LEN)
            self.assertEqual(bytes(buf[:written]), SENDER_KEY)
        finally:
            wally_psbt_free(psbt)

    def test_output_senderkey_absent(self):
        raw = _build_psbt_with_mweb_kernel(sender_key=None)
        psbt = self.parse_bytes(raw)
        try:
            out = psbt.contents.outputs[0]
            buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, written = wally_psbt_output_get_mweb_presign_sender_key(out, buf, buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, 0)
        finally:
            wally_psbt_free(psbt)

    def test_output_senderkey_set_and_clear(self):
        # Start without the field.
        raw = _build_psbt_with_mweb_kernel(sender_key=None)
        psbt = self.parse_bytes(raw)
        try:
            out = psbt.contents.outputs[0]
            new_key = bytes([0x5a] * SCALAR_LEN)
            key_buf, key_buf_len = make_cbuffer(hexlify(new_key).decode())

            # Setter adds it.
            self.assertEqual(WALLY_OK,
                wally_psbt_output_set_mweb_presign_sender_key(out, key_buf, key_buf_len))
            out_buf, out_buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, written = wally_psbt_output_get_mweb_presign_sender_key(out, out_buf, out_buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, SCALAR_LEN)
            self.assertEqual(bytes(out_buf[:written]), new_key)

            # Setter with NULL clears it.
            self.assertEqual(WALLY_OK,
                wally_psbt_output_set_mweb_presign_sender_key(out, None, 0))
            ret, written = wally_psbt_output_get_mweb_presign_sender_key(out, out_buf, out_buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, 0)
        finally:
            wally_psbt_free(psbt)

    def test_output_senderkey_setter_rejects_bad_length(self):
        raw = _build_psbt_with_mweb_kernel(sender_key=None)
        psbt = self.parse_bytes(raw)
        try:
            out = psbt.contents.outputs[0]
            for bad_len in (1, 16, 31, 33, 64):
                buf, buf_len = make_cbuffer('aa' * bad_len)
                self.assertEqual(WALLY_EINVAL,
                    wally_psbt_output_set_mweb_presign_sender_key(out, buf, buf_len))
        finally:
            wally_psbt_free(psbt)

    def test_output_senderkey_getter_rejects_bad_buffer_len(self):
        raw = _build_psbt_with_mweb_kernel()
        psbt = self.parse_bytes(raw)
        try:
            out = psbt.contents.outputs[0]
            for bad_len in (0, 31, 33, 64):
                buf, buf_len = make_cbuffer('00' * max(bad_len, 1))
                ret, _ = wally_psbt_output_get_mweb_presign_sender_key(out, buf, bad_len)
                self.assertEqual(ret, WALLY_EINVAL)
        finally:
            wally_psbt_free(psbt)

    def test_output_senderkey_getter_null_output(self):
        buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
        ret, _ = wally_psbt_output_get_mweb_presign_sender_key(None, buf, buf_len)
        self.assertEqual(ret, WALLY_EINVAL)

    def test_output_senderkey_rejects_malformed_value_len(self):
        # A proprietary key is present but with a bad value length (31B).
        # The getter (length validation only) must reject it.
        magic = b'psbt\xff'
        globals_bytes = (
            _varbuff(bytes([0xfb])) + _varbuff((2).to_bytes(4, 'little'))
          + _varbuff(bytes([0x02])) + _varbuff((2).to_bytes(4, 'little'))
          + _varbuff(bytes([0x04])) + _varbuff(bytes([0x00]))
          + _varbuff(bytes([0x05])) + _varbuff(bytes([0x01]))
          + bytes([0x00])
        )
        bad_key = bytes([0xaa] * 31)
        output_bytes = (
            _varbuff(bytes([0x03])) + _varbuff((1).to_bytes(8, 'little'))
          + _varbuff(bytes([0x04])) + _varbuff(bytes([0x51]))
          + _varbuff(OUT_JADE_KEY) + _varbuff(bad_key)
          + bytes([0x00])
        )
        raw = magic + globals_bytes + output_bytes
        psbt = self.parse_bytes(raw)
        try:
            out = psbt.contents.outputs[0]
            buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, _ = wally_psbt_output_get_mweb_presign_sender_key(out, buf, buf_len)
            self.assertEqual(ret, WALLY_EINVAL)
        finally:
            wally_psbt_free(psbt)

    def test_kernel_stealthkey_roundtrip(self):
        raw = _build_psbt_with_mweb_kernel()
        psbt = self.parse_bytes(raw)
        try:
            self.assertEqual(psbt.contents.num_mweb_kernels, 1)
            kernel_ptr = psbt.contents.mweb_kernels
            self.assertNotEqual(kernel_ptr, None)

            buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, written = wally_psbt_kernel_get_mweb_presign_stealth_key(kernel_ptr, buf, buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, SCALAR_LEN)
            self.assertEqual(bytes(buf[:written]), STEALTH_KEY)
        finally:
            wally_psbt_free(psbt)

    def test_kernel_stealthkey_absent(self):
        raw = _build_psbt_with_mweb_kernel(stealth_key=None)
        psbt = self.parse_bytes(raw)
        try:
            kernel_ptr = psbt.contents.mweb_kernels
            buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, written = wally_psbt_kernel_get_mweb_presign_stealth_key(kernel_ptr, buf, buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, 0)
        finally:
            wally_psbt_free(psbt)

    def test_kernel_stealthkey_set_and_clear(self):
        raw = _build_psbt_with_mweb_kernel(stealth_key=None)
        psbt = self.parse_bytes(raw)
        try:
            kernel_ptr = psbt.contents.mweb_kernels
            new_key = bytes([0x7c] * SCALAR_LEN)
            key_buf, key_buf_len = make_cbuffer(hexlify(new_key).decode())

            self.assertEqual(WALLY_OK,
                wally_psbt_kernel_set_mweb_presign_stealth_key(kernel_ptr, key_buf, key_buf_len))
            out_buf, out_buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, written = wally_psbt_kernel_get_mweb_presign_stealth_key(kernel_ptr, out_buf, out_buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, SCALAR_LEN)
            self.assertEqual(bytes(out_buf[:written]), new_key)

            self.assertEqual(WALLY_OK,
                wally_psbt_kernel_set_mweb_presign_stealth_key(kernel_ptr, None, 0))
            ret, written = wally_psbt_kernel_get_mweb_presign_stealth_key(kernel_ptr, out_buf, out_buf_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, 0)
        finally:
            wally_psbt_free(psbt)

    def test_kernel_stealthkey_setter_rejects_bad_length(self):
        raw = _build_psbt_with_mweb_kernel(stealth_key=None)
        psbt = self.parse_bytes(raw)
        try:
            kernel_ptr = psbt.contents.mweb_kernels
            for bad_len in (1, 16, 31, 33, 64):
                buf, buf_len = make_cbuffer('aa' * bad_len)
                self.assertEqual(WALLY_EINVAL,
                    wally_psbt_kernel_set_mweb_presign_stealth_key(kernel_ptr, buf, buf_len))
        finally:
            wally_psbt_free(psbt)

    def test_kernel_stealthkey_null_kernel(self):
        buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
        ret, _ = wally_psbt_kernel_get_mweb_presign_stealth_key(None, buf, buf_len)
        self.assertEqual(ret, WALLY_EINVAL)
        self.assertEqual(WALLY_EINVAL,
            wally_psbt_kernel_set_mweb_presign_stealth_key(None, buf, buf_len))

    def test_kernel_stealthkey_getter_rejects_bad_buffer_len(self):
        # Symmetric to test_output_senderkey_getter_rejects_bad_buffer_len:
        # the getter is length-strict even when the field is present.
        raw = _build_psbt_with_mweb_kernel()
        psbt = self.parse_bytes(raw)
        try:
            kernel_ptr = psbt.contents.mweb_kernels
            for bad_len in (0, 31, 33, 64):
                buf, _ = make_cbuffer('00' * max(bad_len, 1))
                ret, _written = wally_psbt_kernel_get_mweb_presign_stealth_key(
                    kernel_ptr, buf, bad_len)
                self.assertEqual(ret, WALLY_EINVAL)
        finally:
            wally_psbt_free(psbt)

    def test_kernel_stealthkey_rejects_malformed_value_len(self):
        # Symmetric to test_output_senderkey_rejects_malformed_value_len:
        # a PSBT whose kernel proprietary value has a non-32B length must
        # be rejected by the getter. Build the PSBT manually so we can
        # inject a 31-byte value under the canonical 7-byte JADE key.
        magic = b'psbt\xff'
        globals_bytes = (
            _varbuff(bytes([0xfb])) + _varbuff((2).to_bytes(4, 'little'))
          + _varbuff(bytes([0x02])) + _varbuff((2).to_bytes(4, 'little'))
          + _varbuff(bytes([0x04])) + _varbuff(bytes([0x00]))
          + _varbuff(bytes([0x05])) + _varbuff(bytes([0x01]))
          + _varbuff(bytes([0x92])) + _varbuff(bytes([0x01]))
          + bytes([0x00])
        )
        output_bytes = (
            _varbuff(bytes([0x03])) + _varbuff((1).to_bytes(8, 'little'))
          + _varbuff(bytes([0x04])) + _varbuff(bytes([0x51]))
          + bytes([0x00])
        )
        bad_value = bytes([0xbb] * 31)
        kernel_bytes = (
            _varbuff(KRN_JADE_KEY) + _varbuff(bad_value)
          + bytes([0x00])
        )
        raw = magic + globals_bytes + output_bytes + kernel_bytes

        psbt = self.parse_bytes(raw)
        try:
            kernel_ptr = psbt.contents.mweb_kernels
            buf, buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, _ = wally_psbt_kernel_get_mweb_presign_stealth_key(
                kernel_ptr, buf, buf_len)
            self.assertEqual(ret, WALLY_EINVAL)
        finally:
            wally_psbt_free(psbt)

    def test_strip_clears_only_presign_fields(self):
        # Fixture: 1 MWEB input (with SPENT_OUTPUT_ID + INPUT_AMOUNT),
        #          1 MWEB output (with STEALTH_ADDRESS + COMMIT + JADE presign),
        #          1 MWEB kernel (with JADE presign).
        raw = _build_psbt_with_mweb_kernel()
        psbt = self.parse_bytes(raw)
        try:
            # --- Pre-strip invariants ---
            # JADE proprietary fields present.
            out_buf, out_buf_len = make_cbuffer('00' * SCALAR_LEN)
            ret, written = wally_psbt_output_get_mweb_presign_sender_key(
                psbt.contents.outputs[0], out_buf, out_buf_len)
            self.assertEqual((ret, written), (WALLY_OK, SCALAR_LEN))
            ret, written = wally_psbt_kernel_get_mweb_presign_stealth_key(
                psbt.contents.mweb_kernels, out_buf, out_buf_len)
            self.assertEqual((ret, written), (WALLY_OK, SCALAR_LEN))

            # MWEB_IN_INPUT_AMOUNT (0x97, bit 7 in mweb_keyset) is set and
            # carries the value we inserted in the fixture.
            input_amount_bit = 1 << (0x97 - 0x90)
            self.assertTrue(psbt.contents.inputs[0].mweb_keyset & input_amount_bit)
            self.assertEqual(psbt.contents.inputs[0].mweb_input_amount,
                             MWEB_INPUT_AMOUNT)

            # MWEB output carries stealth address (0x90) and commit (0x91).
            self.assertTrue(psbt.contents.outputs[0].mweb_output_keyset
                            & (1 << (0x90 - 0x90)))
            self.assertTrue(psbt.contents.outputs[0].mweb_output_keyset
                            & (1 << (0x91 - 0x90)))

            # --- Strip ---
            self.assertEqual(WALLY_OK, wally_psbt_strip_mweb_presign_fields(psbt))

            # --- Post-strip: presign fields gone ---
            ret, written = wally_psbt_output_get_mweb_presign_sender_key(
                psbt.contents.outputs[0], out_buf, out_buf_len)
            self.assertEqual((ret, written), (WALLY_OK, 0))
            ret, written = wally_psbt_kernel_get_mweb_presign_stealth_key(
                psbt.contents.mweb_kernels, out_buf, out_buf_len)
            self.assertEqual((ret, written), (WALLY_OK, 0))

            # MWEB_IN_INPUT_AMOUNT cleared (keyset bit AND value zeroed).
            self.assertFalse(psbt.contents.inputs[0].mweb_keyset & input_amount_bit)
            self.assertEqual(psbt.contents.inputs[0].mweb_input_amount, 0)

            # --- Post-strip: MWEB fields that must SURVIVE ---
            # Standard PSBTv2 amount on the output (0x03).
            self.assertEqual(psbt.contents.outputs[0].has_amount, 1)
            self.assertEqual(psbt.contents.outputs[0].amount, 123456789)
            # MWEB output stealth address (0x90) + commit (0x91).
            self.assertTrue(psbt.contents.outputs[0].mweb_output_keyset
                            & (1 << (0x90 - 0x90)))
            self.assertTrue(psbt.contents.outputs[0].mweb_output_keyset
                            & (1 << (0x91 - 0x90)))
            # MWEB input SPENT_OUTPUT_ID (0x90) must survive (only 0x97
            # is in the strip list).
            output_id_bit = 1 << (0x90 - 0x90)
            self.assertTrue(psbt.contents.inputs[0].mweb_keyset & output_id_bit)
            self.assertEqual(
                bytes(psbt.contents.inputs[0].mweb_spent_output_id),
                MWEB_INPUT_OUTPUT_ID)

            # --- Post-strip: wire bytes contain no JADE prefix and still
            # carry the surviving MWEB fields. ---
            post_strip = self.serialize(psbt)
            self.assertNotIn(b'JADE', post_strip)
            self.assertIn(MWEB_OUT_STEALTH_ADDR, post_strip)
            self.assertIn(MWEB_OUT_COMMIT, post_strip)
            self.assertIn(MWEB_INPUT_OUTPUT_ID, post_strip)
            # The 8 bytes that made up the encoded input amount must NOT
            # appear any more (the strip helper removed the field).
            input_amount_le = MWEB_INPUT_AMOUNT.to_bytes(8, 'little')
            self.assertNotIn(input_amount_le, post_strip)
        finally:
            wally_psbt_free(psbt)

    def test_strip_is_noop_when_fields_absent(self):
        # A PSBT with no JADE presign fields AND no MWEB_IN_INPUT_AMOUNT is
        # the only shape for which strip is genuinely a no-op. Build that
        # shape explicitly so the byte-equality assertion is meaningful.
        raw = _build_psbt_with_mweb_kernel(sender_key=None, stealth_key=None,
                                           include_input_amount=False)
        psbt = self.parse_bytes(raw)
        try:
            before = self.serialize(psbt)
            self.assertEqual(WALLY_OK, wally_psbt_strip_mweb_presign_fields(psbt))
            after = self.serialize(psbt)
            self.assertEqual(before, after)
        finally:
            wally_psbt_free(psbt)

    def test_strip_clears_input_amount_only(self):
        # PSBT with no JADE fields but WITH MWEB_IN_INPUT_AMOUNT: strip
        # must clear exactly the input amount and leave everything else.
        raw = _build_psbt_with_mweb_kernel(sender_key=None, stealth_key=None)
        psbt = self.parse_bytes(raw)
        try:
            input_amount_bit = 1 << (0x97 - 0x90)
            self.assertTrue(psbt.contents.inputs[0].mweb_keyset & input_amount_bit)

            self.assertEqual(WALLY_OK, wally_psbt_strip_mweb_presign_fields(psbt))

            self.assertFalse(psbt.contents.inputs[0].mweb_keyset & input_amount_bit)
            self.assertEqual(psbt.contents.inputs[0].mweb_input_amount, 0)

            # SPENT_OUTPUT_ID and the MWEB output fields still present.
            post_strip = self.serialize(psbt)
            self.assertIn(MWEB_INPUT_OUTPUT_ID, post_strip)
            self.assertIn(MWEB_OUT_STEALTH_ADDR, post_strip)
            self.assertIn(MWEB_OUT_COMMIT, post_strip)
            self.assertNotIn(MWEB_INPUT_AMOUNT.to_bytes(8, 'little'), post_strip)
        finally:
            wally_psbt_free(psbt)

    def test_strip_null_psbt(self):
        self.assertEqual(WALLY_EINVAL, wally_psbt_strip_mweb_presign_fields(None))


if __name__ == '__main__':
    unittest.main()

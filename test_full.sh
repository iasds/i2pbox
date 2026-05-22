#!/bin/bash
# i2pbox vs i2pd-tools full comparison (set -e disabled — tools return non-zero for usage)
ORIG_DIR="/tmp/i2pd-tools"
BOX="/home/user/code/i2pbox/i2pbox"
TMP=$(mktemp -d)
PASS=0; FAIL=0

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

assert_eq() {
    local name="$1"; local orig="$2"; local box="$3"
    echo -n "  $name ... "
    if [ "$orig" = "$box" ]; then
        echo -e "${GREEN}PASS${NC}"; PASS=$((PASS+1))
    else
        echo -e "${RED}FAIL${NC}"
        echo "    ORIG: $orig"
        echo "    BOX:  $box"
        FAIL=$((FAIL+1))
    fi
}

assert_file_content_eq() {
    local name="$1"; local f1="$2"; local f2="$3"
    echo -n "  $name ... "
    if diff -q "$f1" "$f2" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"; PASS=$((PASS+1))
    else
        echo -e "${RED}FAIL${NC} (files differ)"
        diff "$f1" "$f2" | head -10
        FAIL=$((FAIL+1))
    fi
}

echo "============================================"
echo "  i2pbox vs i2pd-tools — Full Comparison"
echo "============================================"

# ====== keygen ======
echo ""; echo "=== keygen ==="
cd "$ORIG_DIR"

# Same seed → same key? No, keygen is random. But output format must match.
./keygen "$TMP/k1_orig.dat" 7 2>/dev/null
$BOX keygen "$TMP/k1_box.dat" 7 2>/dev/null

# Compare keyinfo output for both keys (should show same structure)
ORIG_K1=$($BOX keyinfo "$TMP/k1_orig.dat" 2>/dev/null)
BOX_K1=$($BOX keyinfo "$TMP/k1_box.dat" 2>/dev/null)
# Both should end with .b32.i2p
assert_eq "keygen_output_format" \
    "$(echo "$ORIG_K1" | grep -c '\.b32\.i2p$')" \
    "$(echo "$BOX_K1" | grep -c '\.b32\.i2p$')"

# Usage test
ORIG_USAGE_KG=$(cd "$ORIG_DIR" && ./keygen 2>&1); ORIG_RC_KG=$?
BOX_USAGE_KG=$($BOX keygen 2>&1); BOX_RC_KG=$?
assert_eq "keygen_usage_rc" "$ORIG_RC_KG" "$BOX_RC_KG"
assert_eq "keygen_usage_text" "$ORIG_USAGE_KG" "$BOX_USAGE_KG"

# ====== keyinfo ======
echo ""; echo "=== keyinfo ==="

# default
ORIG_KI=$($BOX keyinfo "$TMP/k1_orig.dat" 2>/dev/null)
BOX_KI=$($BOX keyinfo "$TMP/k1_box.dat" 2>/dev/null)
assert_eq "keyinfo_b32_format" \
    "$(echo "$ORIG_KI" | grep -c '\.b32\.i2p$')" \
    "$(echo "$BOX_KI" | grep -c '\.b32\.i2p$')"

# verbose with common key
$BOX keygen "$TMP/shared.dat" 7 2>/dev/null
ORIG_VERBOSE=$(cd "$ORIG_DIR" && ./keyinfo -v "$TMP/shared.dat" 2>&1)
BOX_VERBOSE=$($BOX keyinfo -v "$TMP/shared.dat" 2>&1)
# Both should contain same fields
for field in "Destination:" "Destination Hash:" "B32 Address:" "Signature Type:" "Encryption Type:"; do
    assert_eq "keyinfo_verbose_has_$field" \
        "$(echo "$ORIG_VERBOSE" | grep -c "$field")" \
        "$(echo "$BOX_VERBOSE" | grep -c "$field")"
done

# dest mode
ORIG_DEST=$(cd "$ORIG_DIR" && ./keyinfo -d "$TMP/shared.dat" 2>&1)
BOX_DEST=$($BOX keyinfo -d "$TMP/shared.dat" 2>&1)
assert_eq "keyinfo_dest" "$ORIG_DEST" "$BOX_DEST"

# private mode
ORIG_PRIV=$(cd "$ORIG_DIR" && ./keyinfo -p "$TMP/shared.dat" 2>&1)
BOX_PRIV=$($BOX keyinfo -p "$TMP/shared.dat" 2>&1)
assert_eq "keyinfo_private" "$ORIG_PRIV" "$BOX_PRIV"

# blinded mode (need type 7 or 11)
ORIG_BLIND=$(cd "$ORIG_DIR" && ./keyinfo -b "$TMP/shared.dat" 2>&1)
BOX_BLIND=$($BOX keyinfo -b "$TMP/shared.dat" 2>&1)
assert_eq "keyinfo_blinded" "$ORIG_BLIND" "$BOX_BLIND"

# usage
ORIG_KI_USAGE=$(cd "$ORIG_DIR" && ./keyinfo 2>&1); ORIG_KI_RC=$?
BOX_KI_USAGE=$($BOX keyinfo 2>&1); BOX_KI_RC=$?
assert_eq "keyinfo_usage_rc" "$ORIG_KI_RC" "$BOX_KI_RC"
assert_eq "keyinfo_usage_text" "$ORIG_KI_USAGE" "$BOX_KI_USAGE"

# bad file
ORIG_BADF=$(cd "$ORIG_DIR" && ./keyinfo /nonexistent 2>&1); ORIG_BADF_RC=$?
BOX_BADF=$($BOX keyinfo /nonexistent 2>&1); BOX_BADF_RC=$?
assert_eq "keyinfo_badfile_rc" "$ORIG_BADF_RC" "$BOX_BADF_RC"

# ====== i2pbase64 ======
echo ""; echo "=== i2pbase64 ==="

TEST_STR="Hello I2P Network! Test 12345"

# encode
ORIG_ENC=$(echo "$TEST_STR" | $ORIG_DIR/i2pbase64 2>/dev/null)
BOX_ENC=$(echo "$TEST_STR" | $BOX i2pbase64 2>/dev/null)
assert_eq "base64_encode" "$ORIG_ENC" "$BOX_ENC"

# decode
ORIG_DEC=$(echo "$ORIG_ENC" | $ORIG_DIR/i2pbase64 -d 2>/dev/null)
BOX_DEC=$(echo "$BOX_ENC" | $BOX i2pbase64 -d 2>/dev/null)
assert_eq "base64_decode" "$ORIG_DEC" "$BOX_DEC"

# roundtrip
assert_eq "base64_roundtrip" \
    "$(echo "$TEST_STR" | $ORIG_DIR/i2pbase64 | $ORIG_DIR/i2pbase64 -d)" \
    "$(echo "$TEST_STR" | $BOX i2pbase64 | $BOX i2pbase64 -d)"

# binary data roundtrip
dd if=/dev/urandom of="$TMP/rand.bin" bs=64 count=1 2>/dev/null
ORIG_BIN=$(cat "$TMP/rand.bin" | $ORIG_DIR/i2pbase64)
BOX_BIN=$(cat "$TMP/rand.bin" | $BOX i2pbase64)
assert_eq "base64_binary_encode" "$ORIG_BIN" "$BOX_BIN"

# file mode
echo "$TEST_STR" > "$TMP/b64test"
ORIG_FILE=$($ORIG_DIR/i2pbase64 "$TMP/b64test")
BOX_FILE=$($BOX i2pbase64 "$TMP/b64test")
assert_eq "base64_file" "$ORIG_FILE" "$BOX_FILE"

# usage
ORIG_B64_USAGE=$($ORIG_DIR/i2pbase64 -h 2>&1); ORIG_B64_RC=$?
BOX_B64_USAGE=$($BOX i2pbase64 -h 2>&1); BOX_B64_RC=$?
assert_eq "base64_usage_rc" "$ORIG_B64_RC" "$BOX_B64_RC"

# ====== x25519 ======
echo ""; echo "=== x25519 ==="

ORIG_X=$(cd "$ORIG_DIR" && ./x25519 2>&1)
BOX_X=$($BOX x25519 2>&1)

# Both should output PublicKey: and PrivateKey: lines
for key in "PublicKey:" "PrivateKey:"; do
    assert_eq "x25519_has_$key" \
        "$(echo "$ORIG_X" | grep -c "$key")" \
        "$(echo "$BOX_X" | grep -c "$key")"
done

# Key format: base64, ~43 chars
ORIG_PUB=$(echo "$ORIG_X" | grep "PublicKey:" | sed 's/PublicKey: //')
BOX_PUB=$(echo "$BOX_X" | grep "PublicKey:" | sed 's/PublicKey: //')
assert_eq "x25519_pubkey_length" "${#ORIG_PUB}" "${#BOX_PUB}"

ORIG_X_H=$($ORIG_DIR/x25519 -h 2>&1); ORIG_X_H_RC=$?
BOX_X_H=$($BOX x25519 -h 2>&1); BOX_X_H_RC=$?
assert_eq "x25519_help_rc" "$ORIG_X_H_RC" "$BOX_X_H_RC"

# ====== regaddr ======
echo ""; echo "=== regaddr ==="
$BOX keygen "$TMP/ra_keys.dat" 7 2>/dev/null

ORIG_RA=$(cd "$ORIG_DIR" && ./regaddr "$TMP/ra_keys.dat" myhost.i2p 2>&1)
BOX_RA=$($BOX regaddr "$TMP/ra_keys.dat" myhost.i2p 2>&1)

# Both should start with "myhost.i2p=" and contain "#!sig="
assert_eq "regaddr_prefix" \
    "$(echo "$ORIG_RA" | grep -c '^myhost\.i2p=')" \
    "$(echo "$BOX_RA" | grep -c '^myhost\.i2p=')"
assert_eq "regaddr_sig" \
    "$(echo "$ORIG_RA" | grep -c '#!sig=')" \
    "$(echo "$BOX_RA" | grep -c '#!sig=')"

# Both should verify correctly
echo -n "  regaddr_verify_orig ... "
if cd "$ORIG_DIR" && ./verifyhost "$ORIG_RA" >/dev/null 2>&1; then echo -e "${GREEN}PASS${NC}"; PASS=$((PASS+1))
else echo -e "${RED}FAIL${NC}"; FAIL=$((FAIL+1)); fi

echo -n "  regaddr_verify_box ... "
if cd "$ORIG_DIR" && $BOX verifyhost "$BOX_RA" >/dev/null 2>&1; then echo -e "${GREEN}PASS${NC}"; PASS=$((PASS+1))
else echo -e "${RED}FAIL${NC}"; FAIL=$((FAIL+1)); fi

# Cross-verification: ORIG regaddr verified by BOX verifyhost
echo -n "  regaddr_cross_verify ... "
if cd "$ORIG_DIR" && $BOX verifyhost "$ORIG_RA" >/dev/null 2>&1; then echo -e "${GREEN}PASS${NC}"; PASS=$((PASS+1))
else echo -e "${RED}FAIL${NC}"; FAIL=$((FAIL+1)); fi

# usage
ORIG_RA_U=$(cd "$ORIG_DIR" && ./regaddr 2>&1); ORIG_RA_U_RC=$?
BOX_RA_U=$($BOX regaddr 2>&1); BOX_RA_U_RC=$?
assert_eq "regaddr_usage_rc" "$ORIG_RA_U_RC" "$BOX_RA_U_RC"

# ====== verifyhost ======
echo ""; echo "=== verifyhost ==="

# Valid record
assert_eq "verifyhost_valid_rc" \
    "$(cd $ORIG_DIR && ./verifyhost "$ORIG_RA" >/dev/null 2>&1; echo $?)" \
    "$(cd $ORIG_DIR && $BOX verifyhost "$ORIG_RA" >/dev/null 2>&1; echo $?)"

# Invalid record
ORIG_IV=$(cd "$ORIG_DIR" && ./verifyhost "garbage" 2>&1); ORIG_IV_RC=$?
BOX_IV=$($BOX verifyhost "garbage" 2>&1); BOX_IV_RC=$?
assert_eq "verifyhost_invalid_rc" "$ORIG_IV_RC" "$BOX_IV_RC"

# Tampered record (change one char)
TAMPERED=$(echo "$ORIG_RA" | sed 's/./X/1')
ORIG_TAMPER=$(cd "$ORIG_DIR" && ./verifyhost "$TAMPERED" 2>&1); ORIG_TAMPER_RC=$?
BOX_TAMPER=$($BOX verifyhost "$TAMPERED" 2>&1); BOX_TAMPER_RC=$?
assert_eq "verifyhost_tampered_rc" "$ORIG_TAMPER_RC" "$BOX_TAMPER_RC"
assert_eq "verifyhost_tampered_msg" "$ORIG_TAMPER" "$BOX_TAMPER"

# usage
ORIG_VH_U=$(cd "$ORIG_DIR" && ./verifyhost 2>&1); ORIG_VH_U_RC=$?
BOX_VH_U=$($BOX verifyhost 2>&1); BOX_VH_U_RC=$?
assert_eq "verifyhost_usage_rc" "$ORIG_VH_U_RC" "$BOX_VH_U_RC"
assert_eq "verifyhost_usage_text" "$ORIG_VH_U" "$BOX_VH_U"

# ====== regaddr_3ld ======
echo ""; echo "=== regaddr_3ld ==="

ORIG_3LD_U=$(cd "$ORIG_DIR" && ./regaddr_3ld 2>&1); ORIG_3LD_U_RC=$?
BOX_3LD_U=$($BOX regaddr_3ld 2>&1); BOX_3LD_U_RC=$?
assert_eq "reg3ld_usage_rc" "$ORIG_3LD_U_RC" "$BOX_3LD_U_RC"

# step1
ORIG_S1=$(cd "$ORIG_DIR" && ./regaddr_3ld step1 "$TMP/ra_keys.dat" sub.mydomain.i2p 2>&1)
BOX_S1=$($BOX regaddr_3ld step1 "$TMP/ra_keys.dat" sub.mydomain.i2p 2>&1)
assert_eq "reg3ld_step1_has_action" \
    "$(echo "$ORIG_S1" | grep -c 'addsubdomain')" \
    "$(echo "$BOX_S1" | grep -c 'addsubdomain')"

# step2 (need output from step1 + old keys)
$BOX keygen "$TMP/old_keys.dat" 7 2>/dev/null
echo "$ORIG_S1" > "$TMP/s1_orig.txt"
echo "$BOX_S1" > "$TMP/s1_box.txt"

ORIG_S2=$(cd "$ORIG_DIR" && ./regaddr_3ld step2 "$TMP/s1_orig.txt" "$TMP/old_keys.dat" mydomain.i2p 2>&1)
BOX_S2=$($BOX regaddr_3ld step2 "$TMP/s1_box.txt" "$TMP/old_keys.dat" mydomain.i2p 2>&1)
assert_eq "reg3ld_step2_has_date" \
    "$(echo "$ORIG_S2" | grep -c '#date=')" \
    "$(echo "$BOX_S2" | grep -c '#date=')"
assert_eq "reg3ld_step2_has_olddest" \
    "$(echo "$ORIG_S2" | grep -c '#olddest=')" \
    "$(echo "$BOX_S2" | grep -c '#olddest=')"

# step3
echo "$ORIG_S2" > "$TMP/s2_orig.txt"
echo "$BOX_S2" > "$TMP/s2_box.txt"

ORIG_S3=$(cd "$ORIG_DIR" && ./regaddr_3ld step3 "$TMP/s2_orig.txt" "$TMP/ra_keys.dat" 2>&1)
BOX_S3=$($BOX regaddr_3ld step3 "$TMP/s2_box.txt" "$TMP/ra_keys.dat" 2>&1)
assert_eq "reg3ld_step3_has_sig" \
    "$(echo "$ORIG_S3" | grep -c '#sig=')" \
    "$(echo "$BOX_S3" | grep -c '#sig=')"

# ====== regaddralias ======
echo ""; echo "=== regaddralias ==="
$BOX keygen "$TMP/alias_new.dat" 7 2>/dev/null

ORIG_ALIAS=$(cd "$ORIG_DIR" && ./regaddralias "$TMP/ra_keys.dat" "$TMP/alias_new.dat" myhost.i2p 2>&1)
BOX_ALIAS=$($BOX regaddralias "$TMP/ra_keys.dat" "$TMP/alias_new.dat" myhost.i2p 2>&1)

assert_eq "regalias_has_oldsig" \
    "$(echo "$ORIG_ALIAS" | grep -c '#oldsig=')" \
    "$(echo "$BOX_ALIAS" | grep -c '#oldsig=')"
assert_eq "regalias_has_sig" \
    "$(echo "$ORIG_ALIAS" | grep -c '#sig=')" \
    "$(echo "$BOX_ALIAS" | grep -c '#sig=')"

# usage
ORIG_ALIAS_U=$(cd "$ORIG_DIR" && ./regaddralias 2>&1); ORIG_ALIAS_U_RC=$?
BOX_ALIAS_U=$($BOX regaddralias 2>&1); BOX_ALIAS_U_RC=$?
assert_eq "regalias_usage_rc" "$ORIG_ALIAS_U_RC" "$BOX_ALIAS_U_RC"

# ====== b33address ======
echo ""; echo "=== b33address ==="
DEST64=$($BOX keyinfo -d "$TMP/shared.dat" 2>/dev/null)

ORIG_B33=$(echo "$DEST64" | cd "$ORIG_DIR" && ./b33address 2>&1)
BOX_B33=$(echo "$DEST64" | cd "$ORIG_DIR" && $BOX b33address 2>&1)
assert_eq "b33address_output" "$ORIG_B33" "$BOX_B33"

# Invalid base64
ORIG_B33_BAD=$(echo "not-base64!!!" | cd "$ORIG_DIR" && ./b33address 2>&1)
BOX_B33_BAD=$(echo "not-base64!!!" | cd "$ORIG_DIR" && $BOX b33address 2>&1)
assert_eq "b33address_bad_input" "$ORIG_B33_BAD" "$BOX_B33_BAD"

# ====== offlinekeys ======
echo ""; echo "=== offlinekeys ==="

ORIG_OK=$(cd "$ORIG_DIR" && ./offlinekeys "$TMP/ok_orig.dat" "$TMP/shared.dat" 7 30 2>&1)
BOX_OK=$($BOX offlinekeys "$TMP/ok_box.dat" "$TMP/shared.dat" 7 30 2>&1)

# Both files should be created
assert_eq "offlinekeys_file_exists" \
    "$([ -f "$TMP/ok_orig.dat" ] && echo 1)" \
    "$([ -f "$TMP/ok_box.dat" ] && echo 1)"

# Both should show valid addresses
assert_eq "offlinekeys_output_has_b32" \
    "$(echo "$ORIG_OK" | grep -c '\.b32')" \
    "$(echo "$BOX_OK" | grep -c '\.b32')"

# usage
ORIG_OK_U=$(cd "$ORIG_DIR" && ./offlinekeys 2>&1); ORIG_OK_U_RC=$?
BOX_OK_U=$($BOX offlinekeys 2>&1); BOX_OK_U_RC=$?
assert_eq "offlinekeys_usage_rc" "$ORIG_OK_U_RC" "$BOX_OK_U_RC"

# ====== famtool ======
echo ""; echo "=== famtool ==="

# Generate family
ORIG_FAM_GEN=$(cd "$ORIG_DIR" && ./famtool -g -n testfam -c "$TMP/fam_orig.crt" -k "$TMP/fam_orig.key" 2>&1)
BOX_FAM_GEN=$($BOX famtool -g -n testfam -c "$TMP/fam_box.crt" -k "$TMP/fam_box.key" 2>&1)
assert_eq "famtool_gen_output" "$ORIG_FAM_GEN" "$BOX_FAM_GEN"

# Both cert/key files should exist
for ext in crt key; do
    assert_eq "famtool_${ext}_exists" \
        "$([ -f "$TMP/fam_orig.$ext" ] && echo 1)" \
        "$([ -f "$TMP/fam_box.$ext" ] && echo 1)"
done

# Sign a router.info with the family key
# First create a dummy router.info file (minimal valid format)
# Actually router.info reading fails without valid content. Let's just test the error paths.
# Sign with wrong keys
ORIG_FAM_BAD=$(cd "$ORIG_DIR" && ./famtool -s -n testfam -k "$TMP/fam_orig.key" -i /nonexistent -f /nonexistent 2>&1); ORIG_FAM_BAD_RC=$?
BOX_FAM_BAD=$($BOX famtool -s -n testfam -k "$TMP/fam_orig.key" -i /nonexistent -f /nonexistent 2>&1); BOX_FAM_BAD_RC=$?
assert_eq "famtool_sign_badfile_rc" "$ORIG_FAM_BAD_RC" "$BOX_FAM_BAD_RC"

# Verify
ORIG_FAM_VERIFY=$(cd "$ORIG_DIR" && ./famtool -V -n testfam -c "$TMP/fam_orig.crt" -f /nonexistent 2>&1); ORIG_FAM_VERIFY_RC=$?
BOX_FAM_VERIFY=$($BOX famtool -V -n testfam -c "$TMP/fam_orig.crt" -f /nonexistent 2>&1); BOX_FAM_VERIFY_RC=$?
assert_eq "famtool_verify_badfile_rc" "$ORIG_FAM_VERIFY_RC" "$BOX_FAM_VERIFY_RC"

# usage
ORIG_FAM_U=$(cd "$ORIG_DIR" && ./famtool 2>&1); ORIG_FAM_U_RC=$?
BOX_FAM_U=$($BOX famtool 2>&1); BOX_FAM_U_RC=$?
assert_eq "famtool_usage_rc" "$ORIG_FAM_U_RC" "$BOX_FAM_U_RC"

# ====== routerinfo ======
echo ""; echo "=== routerinfo ==="

# usage
ORIG_RI_U=$(cd "$ORIG_DIR" && ./routerinfo 2>&1); ORIG_RI_U_RC=$?
BOX_RI_U=$($BOX routerinfo 2>&1); BOX_RI_U_RC=$?
assert_eq "routerinfo_usage_rc" "$ORIG_RI_U_RC" "$BOX_RI_U_RC"

# nonexistent file
ORIG_RI_NE=$(cd "$ORIG_DIR" && ./routerinfo /nonexistent 2>&1); ORIG_RI_NE_RC=$?
BOX_RI_NE=$($BOX routerinfo /nonexistent 2>&1); BOX_RI_NE_RC=$?
assert_eq "routerinfo_nonexist_rc" "$ORIG_RI_NE_RC" "$BOX_RI_NE_RC"

# ====== vain ======
echo ""; echo "=== vain ==="

# usage
ORIG_VAIN_U=$(cd "$ORIG_DIR" && ./vain 2>&1); ORIG_VAIN_U_RC=$?
BOX_VAIN_U=$($BOX vain 2>&1); BOX_VAIN_U_RC=$?
assert_eq "vain_usage_rc" "$ORIG_VAIN_U_RC" "$BOX_VAIN_U_RC"

# help
ORIG_VAIN_H=$(cd "$ORIG_DIR" && ./vain -h 2>&1); ORIG_VAIN_H_RC=$?
BOX_VAIN_H=$($BOX vain -h 2>&1); BOX_VAIN_H_RC=$?
assert_eq "vain_help_rc" "$ORIG_VAIN_H_RC" "$BOX_VAIN_H_RC"

# bad prefix
ORIG_VAIN_BAD=$(cd "$ORIG_DIR" && ./vain '!!!' 2>&1); ORIG_VAIN_BAD_RC=$?
BOX_VAIN_BAD=$($BOX vain '!!!' 2>&1); BOX_VAIN_BAD_RC=$?
assert_eq "vain_bad_prefix_rc" "$ORIG_VAIN_BAD_RC" "$BOX_VAIN_BAD_RC"

# ====== autoconf_i2pd ======
echo ""; echo "=== autoconf_i2pd ==="

# Pipe "en" + "1" (clearnet) then answer prompts with defaults
INPUT="en
1
n
n
n
n
n
n
n
n
n
-
n
n
-
-
n
-
n
-
n
-
-
-
n
"

ORIG_AC=$(echo "$INPUT" | timeout 5 $ORIG_DIR/autoconf_i2pd 2>&1 || true)
BOX_AC=$(echo "$INPUT" | timeout 5 $BOX autoconf_i2pd 2>&1 || true)

# Both should output a config with expected keys
for key in "ipv6=" "ipv4=" "floodfill=" "notransit=" "enabled" "port"; do
    assert_eq "autoconf_has_$key" \
        "$(echo "$ORIG_AC" | grep -c "$key")" \
        "$(echo "$BOX_AC" | grep -c "$key")"
done

# Both should have [ntcp2] and [ssu2] sections
for section in "ntcp2" "ssu2" "http"; do
    assert_eq "autoconf_has_section_$section" \
        "$(echo "$ORIG_AC" | grep -c "\[$section\]")" \
        "$(echo "$BOX_AC" | grep -c "\[$section\]")"
done

# ====== SUMMARY ======
echo ""
echo "============================================"
echo -e "  RESULTS: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "============================================"

exit $FAIL

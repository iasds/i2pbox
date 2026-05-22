#!/bin/bash
# i2pbox vs i2pd-tools comparison test
set -e

ORIG_DIR="/tmp/i2pd-tools"
BOX="/home/user/code/i2pbox/i2pbox"
TMPDIR=$(mktemp -d)
PASS=0
FAIL=0

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_one() {
    local name="$1"
    local orig_cmd="$2"
    local box_cmd="$3"
    
    echo -n "  $name ... "
    
    # Run original
    local orig_out="$TMPDIR/${name}_orig"
    local orig_rc=0
    eval "$orig_cmd" > "$orig_out" 2>&1 || orig_rc=$?
    
    # Run i2pbox
    local box_out="$TMPDIR/${name}_box"
    local box_rc=0
    eval "$box_cmd" > "$box_out" 2>&1 || box_rc=$?
    
    if [ "$orig_rc" != "$box_rc" ]; then
        echo -e "${RED}FAIL${NC} (exit: orig=$orig_rc box=$box_rc)"
        FAIL=$((FAIL+1))
        return
    fi

    local orig_empty=0
    local box_empty=0
    [ ! -s "$orig_out" ] && orig_empty=1
    [ ! -s "$box_out" ] && box_empty=1
    
    if [ "$orig_empty" != "$box_empty" ]; then
        echo -e "${RED}FAIL${NC} (output presence differs)"
        FAIL=$((FAIL+1))
        return
    fi
    
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS+1))
}

echo "============================================"
echo "  i2pbox vs i2pd-tools 对比测试"
echo "============================================"
echo ""

# ---- keygen ----
echo "[keygen] 生成随机密钥"
test_one "keygen_default" \
    "cd $ORIG_DIR && ./keygen $TMPDIR/k1_orig.dat" \
    "cd $ORIG_DIR && $BOX keygen $TMPDIR/k1_box.dat"
test_one "keygen_usage" \
    "cd $ORIG_DIR && ./keygen 2>&1" \
    "cd $ORIG_DIR && $BOX keygen 2>&1"

# ---- keyinfo ----
echo "[keyinfo] 查看密钥信息"
test_one "keyinfo_default" \
    "cd $ORIG_DIR && ./keyinfo $TMPDIR/k1_orig.dat" \
    "cd $ORIG_DIR && $BOX keyinfo $TMPDIR/k1_orig.dat"
test_one "keyinfo_verbose" \
    "cd $ORIG_DIR && ./keyinfo -v $TMPDIR/k1_orig.dat" \
    "cd $ORIG_DIR && $BOX keyinfo -v $TMPDIR/k1_orig.dat"
test_one "keyinfo_dest" \
    "cd $ORIG_DIR && ./keyinfo -d $TMPDIR/k1_orig.dat" \
    "cd $ORIG_DIR && $BOX keyinfo -d $TMPDIR/k1_orig.dat"
test_one "keyinfo_usage" \
    "cd $ORIG_DIR && ./keyinfo 2>&1" \
    "cd $ORIG_DIR && $BOX keyinfo 2>&1"

# ---- i2pbase64 ----
echo "[i2pbase64] Base64 编解码"
TEST_STR="Hello I2P Network Test 12345"
test_one "base64_encode" \
    "echo '$TEST_STR' | $ORIG_DIR/i2pbase64" \
    "echo '$TEST_STR' | $BOX i2pbase64"
test_one "base64_decode" \
    "echo '$TEST_STR' | $ORIG_DIR/i2pbase64 | $ORIG_DIR/i2pbase64 -d" \
    "echo '$TEST_STR' | $BOX i2pbase64 | $BOX i2pbase64 -d"

# ---- x25519 ----
echo "[x25519] X25519 密钥生成"
test_one "x25519_gen" \
    "cd $ORIG_DIR && ./x25519" \
    "cd $ORIG_DIR && $BOX x25519"
test_one "x25519_help" \
    "cd $ORIG_DIR && ./x25519 -h" \
    "cd $ORIG_DIR && $BOX x25519 -h"

# ---- verifyhost ----
echo "[verifyhost] 主机记录验证"
cd "$ORIG_DIR"
./keygen "$TMPDIR/vh_keys.dat" 2>/dev/null
HOST_RECORD=$(./regaddr "$TMPDIR/vh_keys.dat" testhost.i2p 2>/dev/null)
test_one "verifyhost_invalid" \
    "cd $ORIG_DIR && ./verifyhost 'invalid-record' 2>&1" \
    "cd $ORIG_DIR && $BOX verifyhost 'invalid-record' 2>&1"
test_one "verifyhost_valid" \
    "cd $ORIG_DIR && ./verifyhost '$HOST_RECORD' 2>&1" \
    "cd $ORIG_DIR && $BOX verifyhost '$HOST_RECORD' 2>&1"
test_one "verifyhost_usage" \
    "cd $ORIG_DIR && ./verifyhost 2>&1" \
    "cd $ORIG_DIR && $BOX verifyhost 2>&1"

# ---- routerinfo ----
echo "[routerinfo] 路由器信息"
test_one "routerinfo_usage" \
    "cd $ORIG_DIR && ./routerinfo 2>&1" \
    "cd $ORIG_DIR && $BOX routerinfo 2>&1"
test_one "routerinfo_nonexist" \
    "cd $ORIG_DIR && ./routerinfo /nonexistent.dat 2>&1" \
    "cd $ORIG_DIR && $BOX routerinfo /nonexistent.dat 2>&1"

# ---- regaddr ----
echo "[regaddr] 地址注册"
test_one "regaddr_reg" \
    "cd $ORIG_DIR && ./regaddr $TMPDIR/k1_orig.dat myhost.i2p" \
    "cd $ORIG_DIR && $BOX regaddr $TMPDIR/k1_orig.dat myhost.i2p"
test_one "regaddr_usage" \
    "cd $ORIG_DIR && ./regaddr 2>&1" \
    "cd $ORIG_DIR && $BOX regaddr 2>&1"

# ---- regaddr_3ld ----
echo "[regaddr_3ld] 3LD 注册"
test_one "reg3ld_usage" \
    "cd $ORIG_DIR && ./regaddr_3ld 2>&1" \
    "cd $ORIG_DIR && $BOX regaddr_3ld 2>&1"
test_one "reg3ld_step1" \
    "cd $ORIG_DIR && ./regaddr_3ld step1 $TMPDIR/k1_orig.dat test3ld.i2p" \
    "cd $ORIG_DIR && $BOX regaddr_3ld step1 $TMPDIR/k1_orig.dat test3ld.i2p"

# ---- regaddralias ----
echo "[regaddralias] 地址别名"
test_one "regalias_usage" \
    "cd $ORIG_DIR && ./regaddralias 2>&1" \
    "cd $ORIG_DIR && $BOX regaddralias 2>&1"

# ---- offlinekeys ----
echo "[offlinekeys] 离线密钥"
test_one "offlinekeys_gen" \
    "cd $ORIG_DIR && ./offlinekeys $TMPDIR/ok_orig.dat $TMPDIR/k1_orig.dat" \
    "cd $ORIG_DIR && $BOX offlinekeys $TMPDIR/ok_box.dat $TMPDIR/k1_orig.dat"
test_one "offlinekeys_usage" \
    "cd $ORIG_DIR && ./offlinekeys 2>&1" \
    "cd $ORIG_DIR && $BOX offlinekeys 2>&1"

# ---- b33address ----
echo "[b33address] b33 地址转换"
DEST_B64=$(cd $ORIG_DIR && ./keyinfo -d $TMPDIR/k1_orig.dat 2>/dev/null)
test_one "b33address" \
    "echo '$DEST_B64' | cd $ORIG_DIR && ./b33address" \
    "echo '$DEST_B64' | cd $ORIG_DIR && $BOX b33address"

# ---- famtool ----
echo "[famtool] 家族工具"
test_one "famtool_usage" \
    "cd $ORIG_DIR && ./famtool 2>&1" \
    "cd $ORIG_DIR && $BOX famtool 2>&1"

# ---- vain ----
echo "[vain] 靓号地址"
test_one "vain_usage" \
    "cd $ORIG_DIR && ./vain 2>&1" \
    "cd $ORIG_DIR && $BOX vain 2>&1"

# ---- autoconf_i2pd ----
echo "[autoconf_i2pd] 自动配置"
test_one "autoconf_lang" \
    "cd $ORIG_DIR && echo 'en' | timeout 2 ./autoconf_i2pd 2>&1 || true" \
    "cd $ORIG_DIR && echo 'en' | timeout 2 $BOX autoconf_i2pd 2>&1 || true"

echo ""
echo "============================================"
echo -e "  结果: ${GREEN}$PASS 通过${NC}, ${RED}$FAIL 失败${NC}"
echo "============================================"

exit $FAIL

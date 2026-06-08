#!/usr/bin/env python3
"""
Integration test for Sovereign tiered memory patch.
Tests hot/warm overflow, recall, and schema.
"""
import sys, os, json, tempfile, time
from pathlib import Path

# Point to fork
sys.path.insert(0, '/mnt/c/VaultSentinel/HermesCore')
sys.path.insert(0, '/mnt/c/VaultSentinel/Sovereign')

from tools.memory_tool import MemoryStore, ENTRY_DELIMITER, MEMORY_SCHEMA, _warm_count, _warm_entries_list

failures = 0

def check(name, condition, detail=""):
    global failures
    if condition:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name} — {detail}")
        failures += 1

# === Test 1: Schema tests ===
print("\n=== Schema tests ===")
params = MEMORY_SCHEMA["parameters"]
check("type is object", params["type"] == "object")
check("required fields", params["required"] == ["action", "target"])
check("all actions present", params["properties"]["action"]["enum"] ==
      ["add", "replace", "remove", "read", "read_warm", "warm_to_hot"])
check("targets", params["properties"]["target"]["enum"] == ["memory", "user"])
check("JSON serializable", isinstance(json.dumps(MEMORY_SCHEMA), str))

# === Test 2: Basic operations with isolated dir ===
print("\n=== Basic operations ===")
TEST_DIR = Path(tempfile.mkdtemp(prefix="sovereign_mem_test_"))
os.environ["HERMES_HOME"] = str(TEST_DIR)
print(f"Test dir: {TEST_DIR}")

store = MemoryStore(memory_char_limit=500, user_char_limit=500)
store.load_from_disk()  # reads empty files

# Add entries
r = json.loads(json.dumps(store.add('memory', 'Entry one')))
check("add entry one", r["success"], str(r))
check("entry count 1", len(store.memory_entries) == 1)
check("usage shows", "chars" in r.get("usage", ""))

r = json.loads(json.dumps(store.add('memory', 'Entry two')))
check("add entry two", r["success"])

r = json.loads(json.dumps(store.add('user', 'User fact')))
check("add user entry", r["success"])

# Read
r = json.loads(json.dumps(store.add('memory', 'Entry three')))
check("add entry three", r["success"])

# Remove
r = json.loads(json.dumps(store.remove('memory', 'one')))
check("remove entry one", r["success"])

# Wrong remove
r = json.loads(json.dumps(store.remove('memory', 'nonexistent')))
check("remove nonexistent fails", not r["success"])

# === Test 3: Warm tier overflow ===
print("\n=== Warm tier overflow ===")
os.environ["HERMES_HOME"] = str(TEST_DIR)
store2 = MemoryStore(memory_char_limit=50, user_char_limit=50)
store2.load_from_disk()

# First entry fits
r = json.loads(json.dumps(store2.add('memory', 'Short')))
check("small entry fits", r["success"])

# Second entry should overflow first
r = json.loads(json.dumps(store2.add('memory', 'Longer entry content to trigger overflow')))
check("overflow succeeds", r["success"], str(r))
check("overflow indicator", r.get("warm_overflow", 0) > 0, str(r))

# Check warm tier
warm = json.loads(json.dumps(store2.read_warm('memory')))
check("warm tier has entry", warm["entry_count"] >= 1, str(warm))

# System prompt rendering shows warm indicator
block = store2._render_block('memory', store2.memory_entries)
check("render block shows warm", "+" in block and "warm" in block)

# === Test 4: Warm to hot recall ===
print("\n=== Warm to hot recall ===")
warm = json.loads(json.dumps(store2.read_warm('memory')))
if warm["entry_count"] > 0:
    warm_key = warm["entries"][0]["key"]
    # Remove the warm_ prefix for recall
    key_suffix = warm_key.replace("memory_warm_", "")
    r = json.loads(json.dumps(store2.warm_to_hot('memory', key_suffix)))
    check("recall to hot succeeds", r["success"], str(r))

    # Check that the recalled entry text is now in hot tier
    recalled_value = warm["entries"][0]["value"]
    check("recalled entry in hot", any(recalled_value in e for e in store2.memory_entries))

# === Test 5: Render block edge cases ===
print("\n=== Render block formatting ===")

# Empty hot with no warm entries shows header if warm_count > 0
empty_store = MemoryStore(memory_char_limit=200, user_char_limit=200)
empty_store.memory_entries = []
warm_count = _warm_count('memory')
# This is the normal path: when warm entries exist but hot is empty,
# we show a minimal header so the agent knows warm data is available
if warm_count > 0:
    block = empty_store._render_block('memory', [])
    check("empty hot + warm shows header", "+" in block and "warm" in block)
else:
    # No warm entries and no hot entries = empty block
    block = empty_store._render_block('memory', [])
    check("no entries anywhere = empty block", block == "")

# Empty hot + warm entries shows header
empty_store_2 = MemoryStore(memory_char_limit=200, user_char_limit=200)
empty_store_2.memory_entries = []
# Manually put something in warm so _warm_count returns > 0
# This is normally triggered by overflow but let's verify _warm_count works
warm_count = _warm_count('memory')
# Note: warm_count may be >0 from the store2 test above (same section = memory)
# That's fine — the test is just checking the render path
if warm_count > 0:
    block = empty_store_2._render_block('memory', [])
    check("empty hot + warm shows header", "+" in block and "warm" in block)

# === Test 6: Success response includes warm count ===
print("\n=== Success response ===")
r = json.loads(json.dumps(store2._success_response('memory')))
check("response has warm_entries key", "warm_entries" in r)
check("warm_entries is int", isinstance(r["warm_entries"], int))

# === Summary ===
print(f"\n{'='*50}")
if failures == 0:
    print("ALL TESTS PASSED")
else:
    print(f"{failures} TEST(S) FAILED")

import shutil
shutil.rmtree(TEST_DIR, ignore_errors=True)
sys.exit(0 if failures == 0 else 1)

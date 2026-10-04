#!/usr/bin/env python3
"""
CyberHash Toolkit
A learning-focused CLI for hashing, hash identification, and basic hash
analysis. Educational use only - do not use against systems or data you
do not own or have explicit permission to test.
"""

import os
import sys

from core import hasher, identifier, analyzer, encoder, history

BANNER = r"""
   ___      _              _  _              _
  / __\   _| |__   ___ _ __| || | __ _ ___| |__
 / /  | | | | '_ \ / _ \ '__| || |/ _` / __| '_ \
/ /___| |_| | |_) |  __/ |  |__   _| (_| \__ \ | | |
\____/ \__, |_.__/ \___|_|     |_|  \__,_|___/_| |_|
       |___/            CyberHash Toolkit  (v1.0)
"""


def pause():
    input("\nPress Enter to continue...")


def menu():
    print(BANNER)
    print("1. Hash Generator (text or file)")
    print("2. Hash Identifier")
    print("3. Hash Analysis (compare / decode / wordlist / brute-force)")
    print("4. Encoding Tools (Base64 / Hex / URL / ROT13)")
    print("5. Hash History")
    print("0. Exit")
    return input("\nSelect an option: ").strip()


# ---------------------------------------------------------------- generator
def menu_generator():
    print("\n-- Hash Generator --")
    print("1. Hash text")
    print("2. Hash file")
    choice = input("Select: ").strip()

    if choice == "1":
        text = input("Text to hash: ")
        print(f"\nAvailable algorithms: {', '.join(hasher.list_algorithms())}")
        algo = input("Algorithm (or 'all'): ").strip().lower()
        try:
            if algo == "all":
                results = hasher.hash_text_all(text)
                for name, digest in results.items():
                    print(f"  {name:<10} {digest}")
                history.add_entry("hash_text_all", {"length": len(text)})
            else:
                digest = hasher.hash_text(text, algo)
                print(f"\n{algo}: {digest}")
                history.add_entry("hash_text", {"algorithm": algo, "digest": digest})
        except ValueError as e:
            print(f"Error: {e}")

    elif choice == "2":
        path = input("File path: ").strip()
        if not os.path.isfile(path):
            print("File not found.")
            return
        print(f"\nAvailable algorithms: {', '.join(hasher.list_algorithms())}")
        algo = input("Algorithm (or 'all'): ").strip().lower()
        try:
            if algo == "all":
                results = hasher.hash_file_all(path)
                for name, digest in results.items():
                    print(f"  {name:<10} {digest}")
                history.add_entry("hash_file_all", {"file": path})
            else:
                digest = hasher.hash_file(path, algo)
                print(f"\n{algo}: {digest}")
                history.add_entry("hash_file", {"algorithm": algo, "file": path, "digest": digest})
        except ValueError as e:
            print(f"Error: {e}")


# ---------------------------------------------------------------- identifier
def menu_identifier():
    print("\n-- Hash Identifier --")
    value = input("Hash to identify: ").strip()
    results = identifier.identify(value)
    if not results:
        print("Nothing to identify.")
        return
    print("\nPossible algorithm(s), ranked by confidence:")
    for r in results:
        print(f"  {r['algorithm']:<20} {r['confidence']}% confidence")
    history.add_entry("identify", {"input_length": len(value), "top_guess": results[0]["algorithm"]})


# ---------------------------------------------------------------- analysis
def menu_analysis():
    print("\n-- Hash Analysis --")
    print("1. Compare two hashes")
    print("2. Hash decoder (bundled dictionary)")
    print("3. Wordlist attack (your file)")
    print("4. Bounded brute-force demo")
    choice = input("Select: ").strip()

    if choice == "1":
        h1 = input("Hash A: ").strip()
        h2 = input("Hash B: ").strip()
        match = analyzer.compare_hashes(h1, h2)
        print("MATCH" if match else "NO MATCH")
        history.add_entry("compare", {"match": match})

    elif choice == "2":
        target = input("Target hash: ").strip()
        print(f"Available algorithms: {', '.join(hasher.list_algorithms())}")
        algo = input("Algorithm used to produce it: ").strip().lower()
        result = analyzer.decode_hash(target, algo)
        _print_attack_result(result)
        history.add_entry("decode", {"algorithm": algo, "found": result["found"]})

    elif choice == "3":
        target = input("Target hash: ").strip()
        print(f"Available algorithms: {', '.join(hasher.list_algorithms())}")
        algo = input("Algorithm used to produce it: ").strip().lower()
        path = input("Wordlist file path (blank = bundled sample): ").strip() or None
        result = analyzer.wordlist_attack(target, algo, path)
        _print_attack_result(result)
        history.add_entry("wordlist_attack", {"algorithm": algo, "found": result["found"]})

    elif choice == "4":
        target = input("Target hash: ").strip()
        print(f"Available algorithms: {', '.join(hasher.list_algorithms())}")
        algo = input("Algorithm used to produce it: ").strip().lower()
        charset = input("Charset (e.g. abc123, default = a-z0-9): ").strip() or "abcdefghijklmnopqrstuvwxyz0123456789"
        try:
            max_len = int(input(f"Max length (<= {analyzer.MAX_BRUTEFORCE_LENGTH}): ").strip() or "3")
        except ValueError:
            max_len = 3
        keyspace = analyzer.keyspace_size(len(charset), max_len)
        print(f"Keyspace to search: {keyspace:,} candidates. This is why length/charset matter.")
        try:
            result = analyzer.bounded_bruteforce(target, algo, charset, max_len)
            _print_attack_result(result)
            if result.get("capped"):
                print("(Stopped: hit the demo's attempt ceiling. This is a teaching cap, not a real tool.)")
            history.add_entry("bruteforce", {"algorithm": algo, "found": result["found"], "max_len": max_len})
        except ValueError as e:
            print(f"Error: {e}")


def _print_attack_result(result):
    if result["found"]:
        print(f"\nFOUND after {result['attempts']} attempt(s): '{result['plaintext']}'")
    else:
        print(f"\nNot found after {result['attempts']} attempt(s).")


# ---------------------------------------------------------------- encoding
def menu_encoding():
    print("\n-- Encoding Tools --")
    print("Tools: base64, hex, url, rot13")
    tool = input("Tool: ").strip().lower()
    mode = input("Mode (encode/decode): ").strip().lower()
    text = input("Text: ")
    try:
        result = encoder.run(tool, mode, text)
        print(f"\nResult: {result}")
        history.add_entry("encode", {"tool": tool, "mode": mode})
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Could not {mode} that input as {tool}: {e}")


# ---------------------------------------------------------------- history
def menu_history():
    print("\n-- Hash History --")
    print("1. View recent")
    print("2. Clear history")
    choice = input("Select: ").strip()
    if choice == "1":
        entries = history.get_history()
        if not entries:
            print("No history yet.")
        for e in entries:
            print(f"  [{e['timestamp']}] {e['operation']}: {e['detail']}")
    elif choice == "2":
        history.clear_history()
        print("History cleared.")


def main():
    while True:
        choice = menu()
        try:
            if choice == "1":
                menu_generator()
            elif choice == "2":
                menu_identifier()
            elif choice == "3":
                menu_analysis()
            elif choice == "4":
                menu_encoding()
            elif choice == "5":
                menu_history()
            elif choice == "0":
                print("Goodbye.")
                sys.exit(0)
            else:
                print("Invalid option.")
        except KeyboardInterrupt:
            print("\nGoodbye.")
            sys.exit(0)
        pause()


if __name__ == "__main__":
    main()

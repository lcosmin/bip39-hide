"""
DISCLAIMER: use at your own risk!

This tool attempts to make it harder for an attacker to identify your printed BIP39 passphrase by
placing the words inside a 16x16 matrix of other valid BIP39 words, making it more difficult for
an attacker to determine the correct ones without having the password.

"""

import argparse
import unicodedata
import re
import os
import sys
import struct
from typing import List
from hashlib import sha256


def rand_uint32() -> int:
    return struct.unpack("<I", os.urandom(4))[0]


def choice(l: List[str]) -> str:
    return l[rand_uint32() % len(l)]


def load_wordlist(path: str) -> List[str]:
    words = []
    with open(path) as f:
        for line in f:
            for word in re.split(r"\W+", line):
                word = word.strip().lower()
                if word:
                    words.append(word)
    return words


def kdf(password: str) -> bytes:
    # Normalize the password string to the NFC form, so that the utf-8 bytes look the
    # same no matter on which system the user types the password
    buf = unicodedata.normalize("NFC", password).encode("utf-8")

    # for the moment, a simple sha256 (100k times)
    for _ in range(100000):
        buf = sha256(buf).digest()

    return buf


def pretty_print_matrix(m: list):
    PAD = 1
    max_len = max(map(len, m)) + PAD

    # print header
    print(" " * 3, end="")
    for col in range(16):
        print(f"{col:X}".center(max_len), end="")
    print()

    for row in range(16):
        print(f"{row:X}".ljust(4), end="")
        for col in range(16):
            print(m[row * 16 + col].ljust(max_len), end="")
        print()


def encode_bip(buf: list, passphrase: list, password: bytes) -> list:
    # The encoding is simple. Need to hide 24 words in a 16x16 matrix.
    # Get each byte of the password and extract the row and col coordinates
    # in the buffer where to put the bip word. So, for example if the current
    # password byte is 0xC1, then the current bip word will be stored at
    # row 0xC and column 0x1.

    for word, pbyte in zip(passphrase, password):
        # calculate the index from row and col
        index = ((pbyte & 0b11110000) >> 4) * 16 + (pbyte & 0b00001111)
        buf[index] = word

    return buf


def main():
    p = argparse.ArgumentParser()

    p.add_argument("-p", "--password", help="password used to scramble the words")
    p.add_argument("-w", "--words", help="file containing the BIP39 words", default="bip-words.txt")


    p.add_argument("--hide", help="Hide the BIP39 passphrase from this file")
    p.add_argument("--unhide", action="store_true", help="Show coordinates for recovering the passphrase")


    args = p.parse_args()

    bip_words = load_wordlist(args.words)

    if not args.password:
        import getpass
        p1 = getpass.getpass(prompt="enter password: ").strip()

        if args.hide:
            p2 = getpass.getpass(prompt="enter password again: ").strip()

            if p1 != p2:
                print("passwords mismatch!", file=sys.stderr)
                sys.exit(1)

        #print("your password: '{}'".format(p1))

        args.password = p1

    password = kdf(args.password)

    if args.hide:
        # create a buffer filled with randomly chosen words from the BIP list
        wb = [choice(bip_words) for _ in range(256)]

        # read the words to hide from the specified file. If file is '-', read from stdin
        if args.hide == "-":
            pp = input("enter your BIP39 passphrase: ")
            passphrase = [x.strip().lower() for x in re.split(r"\W+", pp) if x.strip()]
        else:
            passphrase = load_wordlist(args.hide)

        # make sure the passphrase words are also in the loaded word file
        # TODO: suggest possible valid words in case of typos?
        for word in passphrase:
            # linear searching a list is not optimal, but the code also isn't performance critical.
            # TODO: could use bisect, as the BIP39 wordlist is usually sorted
            if word not in bip_words:
                print("passphrase word '{}' not found in the BIP39 wordlist".format(word), file=sys.stderr)
                sys.exit(1)

        # place them in position according to the
        encode_bip(wb, passphrase, password)

        # display result
        pretty_print_matrix(wb)

    if args.unhide:
        for pbyte in password:
            print("{:X}:{:X} ".format((pbyte & 0b11110000) >> 4, pbyte & 0b00001111), end="")
        print()

if __name__ == "__main__":
    main()


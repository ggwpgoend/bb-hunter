#!/usr/bin/env python3
import sys

def space2comment(payload):
    return payload.replace(" ", "/**/")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(space2comment(sys.argv[1]))
    else:
        print("Usage: python3 space2comment.py '<payload>'")

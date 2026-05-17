#!/usr/bin/env python3
import sys
import random

def randomcase(payload):
    result = ""
    for char in payload:
        if char.isalpha():
            result += char.upper() if random.choice([True, False]) else char.lower()
        else:
            result += char
    return result

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(randomcase(sys.argv[1]))
    else:
        print("Usage: python3 randomcase.py '<payload>'")

import hashlib
import os


def sha256_file(path):

    hasher = hashlib.sha256()

    with open(path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


def sha256_bytes(data):

    return hashlib.sha256(data).hexdigest()


def compare_hashes(first, second):

    return first.lower() == second.lower()
# Build Your Own Password Cracker

This is a solution to the problem posed at https://codingchallenges.fyi/challenges/challenge-password-cracker

Rainbow tables are implemented as per https://en.wikipedia.org/wiki/Rainbow_table and
https://en.wikipedia.org/wiki/Rainbow_table#cite_note-ophpaper-1.

## Features

- Brute force: taking an alphabet and a maximum password length, find a password that has the given hash.
- Index: index a password file for O(logN) searching by hash.
- Dictionary: find a password for the given hash using a password file and an index file.
- Rainbow Index: build a rainbow table of the given dimensions.
- Rainbow: search for a password in a rainbow table for the given hash.

## Example usage

- ```cracker --brute-force --hash 7a95bf926a0333f57705aeac07a362a2 --max-password-length 4```
- ```cracker --index --index-file=index.bin --password-file=passwords.txt```
- ```cracker --dictionary --hash 2bdb742fc3d075ec6b73ea414f27819a --index-file=index.bin --password-file=passwords.txt```
- ```cracker --rainbow-index --index-file=rainbow.bin --password-length 4 --table-width=1024 --table-length=8192 --alphabet-regex '[A-Z]'```
- ```cracker --rainbow --hash 7a95bf926a0333f57705aeac07a362a2 --index-file=rainbow.bin --password-length 4 --table-width=1024 --table-length=8192 --alphabet-regex '[A-Z]'```

## Results

- Brute forcing 7a95bf926a0333f57705aeac07a362a2 to give PASS: 0.016s
- Brute forcing 08054846bbc9933fd0395f8be516a9f9 to give CODE: 0.022s
- Indexing the crackstation shorter list: 52.141s
- Dictionary attacking 2bdb742fc3d075ec6b73ea414f27819a to give PASSW0RD!: 0.005s
- Creating a 1024x8192 rainbow table for passwords matching [A-Z]{4}: 0.677s
- Rainbow table lookup for 7a95bf926a0333f57705aeac07a362a2 to give PASS: 0.674s
- Rainbow table lookup for 08054846bbc9933fd0395f8be516a9f9 to give CODE: 0.286s

# Getting Started

## Pre-requisites

You will need to be able to build and run container images using docker or a docker compatible command line interface
(e.g. podman). Read the integration test script below for further information.

#### Steps

1. docker build -t cc-fyi-cracker .
2. docker run -it -v $(pwd):$(pwd):ro cc-fyi-cracker $(pwd)/scripts/integration_test.sh

#!/usr/bin/env bash

set -x

PROJECT_DIR="$(readlink -f "$(dirname "$0")/..")"

# Specify WORK_DIR in the environment to (re)use an existing directory
if [ -z "$WORK_DIR" ]; then
  trap 'cd / && /bin/rm -rf ${WORK_DIR}' EXIT
  WORK_DIR="$(mktemp -d "/tmp/$(basename $0).$$.tmpdir.XXXXXX")"
fi

[ -d "$WORK_DIR" ] || exit 1
cd "$WORK_DIR" || exit 1

# If there's no $WORK_DIR/bin/cracker, build it
if [ ! -x bin/cracker ]; then
  mkdir -p build || exit 1
  cd build || exit 1
  mkdir -p .conan || exit 1
  . /opt/rh/gcc-toolset-13/enable || exit 1
  CONAN_USER_HOME=$(pwd) conan install "$PROJECT_DIR" --build missing -s compiler.libcxx=libstdc++11 -s build_type=Release || exit 1
  cmake -DCMAKE_BUILD_TYPE=Release "$PROJECT_DIR" || exit 1
  cmake --build . --parallel || exit 1
  cmake --install . --prefix "$WORK_DIR" || exit 1
fi

cd "$WORK_DIR" || exit 1
[ -x bin/cracker ] || exit 1

# Brute force the hashes for PASS and CODE
password=$(time bin/cracker --brute-force --hash 7a95bf926a0333f57705aeac07a362a2 --max-password-length 4 --alphabet-regex '[A-Z]')
[ "$password" == "PASS" ] || exit 1
password=$(time bin/cracker --brute-force --hash 08054846bbc9933fd0395f8be516a9f9 --max-password-length 4 --alphabet-regex '[A-Z]')
[ "$password" == "CODE" ] || exit 1

# Download the crackstation shorter list
if [ ! -f passwords.txt ]; then
  curl -sL https://crackstation.net/files/crackstation-human-only.txt.gz | gunzip > passwords.txt
fi

# Index it
if [ ! -f dictionary-index.bin ]; then
  time bin/cracker --index --index-file dictionary-index.bin --password-file passwords.txt
fi

# Look up a hash using the index
password=$(time bin/cracker --dictionary --hash 2bdb742fc3d075ec6b73ea414f27819a --index-file dictionary-index.bin --password-file passwords.txt)
[ "$password" == "PASSW0RD!" ] || exit 1

# Create a rainbow table with chains of 1024 and length 8192.
if [ ! -f rainbow-index.bin ]; then
  time bin/cracker --rainbow-index --index-file rainbow-index.bin --password-length 4 --table-width=1024 --table-length=8192 --alphabet-regex '[A-Z]'
fi

# Use it to lookup PASS from its hash
password=$(time bin/cracker --rainbow --hash 7a95bf926a0333f57705aeac07a362a2 --index-file=rainbow-index.bin --password-length 4 --table-width=1024 --table-length=8192 --alphabet-regex '[A-Z]')
[ "$password" == "PASS" ] || exit 1

# Use it to lookup CODE from its hash
password=$(time bin/cracker --rainbow --hash 08054846bbc9933fd0395f8be516a9f9 --index-file=rainbow-index.bin --password-length 4 --table-width=1024 --table-length=8192 --alphabet-regex '[A-Z]')
[ "$password" == "CODE" ] || exit 1

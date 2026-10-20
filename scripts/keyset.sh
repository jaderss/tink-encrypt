#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
./mvnw -q compile
classpath=$(./mvnw -q dependency:build-classpath -Dmdep.includeScope=runtime -Dmdep.outputFile=/dev/stdout)
java -cp "target/classes:$classpath" dev.jaderss.encrypt.keyset.Keysets "$@"

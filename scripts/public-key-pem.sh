#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
./mvnw -q -Ppem-preview compile
classpath=$(./mvnw -q dependency:build-classpath -Dmdep.includeScope=runtime -Dmdep.outputFile=/dev/stdout)
java --enable-preview -cp "target/preview/classes:$classpath" dev.jaderss.encrypt.pem.PublicKeyPem

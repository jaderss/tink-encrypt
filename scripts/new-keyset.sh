#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
classpath=$(./mvnw -q dependency:build-classpath -Dmdep.includeScope=runtime -Dmdep.outputFile=/dev/stdout)
java -cp "$classpath" scripts/NewKeyset.java

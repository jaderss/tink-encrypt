#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/.."
runs=${RUNS:-10}
work=target/startup
jar=encrypt-0.0.1-SNAPSHOT.jar

./mvnw -q -B package -DskipTests 2>/dev/null
rm -rf "$work"
mkdir -p "$work"
java -Djarmode=tools -jar "target/$jar" extract --destination "$work/extracted" >/dev/null
ENCRYPT_KEYSET=$(scripts/keyset.sh new 2>/dev/null)
export ENCRYPT_KEYSET

java -XX:AOTCacheOutput="$work/app.aot" -Dspring.context.exit=onRefresh \
    -jar "$work/extracted/$jar" >"$work/training.log" 2>&1

start_once() {
    local log="$work/run.log"
    java "$@" --server.port=0 >"$log" 2>&1 &
    local pid=$!
    for _ in $(seq 300); do
        grep -q 'Started EncryptApplication' "$log" && break
        sleep 0.1
    done
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    grep -o 'Started EncryptApplication in [0-9.,]* seconds (process running for [0-9.,]*)' "$log" \
        | tr ',' '.' | awk '{print $4, $9}' | tr -d ')'
}

median() {
    sort -n | awk '{a[NR]=$1} END {print (NR % 2) ? a[(NR+1)/2] : (a[NR/2] + a[NR/2+1]) / 2}'
}

measure() {
    local label=$1
    shift
    start_once "$@" >/dev/null
    local results
    results=$(for _ in $(seq "$runs"); do start_once "$@"; done)
    printf '| %s | %s s | %s s |\n' "$label" \
        "$(echo "$results" | awk '{print $1}' | median)" \
        "$(echo "$results" | awk '{print $2}' | median)"
}

echo "$(java -version 2>&1 | head -1), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $runs runs each, median"
echo
echo '| Configuration | Context started | Process ready |'
echo '|---|---|---|'
measure 'Fat jar' -jar "target/$jar"
measure 'Extracted jar' -jar "$work/extracted/$jar"
measure 'Extracted jar with AOT cache' -XX:AOTMode=on -XX:AOTCache="$work/app.aot" -jar "$work/extracted/$jar"
echo
echo "AOT cache size: $(du -h "$work/app.aot" | cut -f1)"

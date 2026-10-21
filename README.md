# tink-encrypt

[![CI](https://github.com/jaderss/tink-encrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/jaderss/tink-encrypt/actions/workflows/ci.yml) [![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=jaderss_tink-encrypt&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=jaderss_tink-encrypt)

An encryption service for sensitive fields, such as SSNs and account numbers, built on Google Tink, Spring Boot 4.1 and Java 25. Callers send a value plus the tenant and field it belongs to; the service returns a ciphertext that only decrypts under that same tenant and field.

## What it does

- Encrypts and decrypts with AES-256-GCM through Tink, with the tenant and field bound to every ciphertext as associated data.
- Rotates keys without breaking stored data, and re-encrypts old ciphertext under the newest key without returning the plaintext.
- Keeps the keyset out of configuration in production by wrapping it with an AWS KMS key.
- Accepts values encrypted client-side to an HPKE public key and stores them in the same format.
- Derives per-tenant keys with HKDF through the Java 25 KDF API.
- Reports every failure as RFC 9457 Problem Details, carries a request id in a `ScopedValue`, and emits a JFR event per operation.

## Threat model

It protects against:

- A leaked database or backup. Stored values are ciphertext, and the keys are not stored with them.
- Ciphertext moved between records. A value encrypted for one tenant or field fails to decrypt for any other.
- A leaked environment or config file, when the `aws` profile is used. The keyset there is wrapped by a KMS key that never leaves KMS.
- Plaintext exposure between a client and the service, when clients encrypt to the hybrid public key.

It does not protect against:

- Anyone who can call `/decrypt`. The service has no authentication; it belongs behind a gateway that authenticates callers and decides who may decrypt which tenant's data.
- A compromised host. The running process holds the data keys in memory.
- Length leaks. A ciphertext reveals the approximate length of its plaintext.
- Lost keys. Data encrypted under a key that is destroyed is gone for good.

## Run it

Java 25 is required. Docker is needed only for the test suite.

```bash
export ENCRYPT_KEYSET=$(scripts/keyset.sh new)
./mvnw spring-boot:run
```

```bash
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"context":{"tenantId":"acme","field":"ssn"},"plaintext":"123-45-6789"}'
```

`http/sample.http` holds the same calls for IntelliJ IDEA or the VS Code REST Client, chaining the ciphertext from encrypt into decrypt and re-encrypt.

| Profile | Adds | Variables |
|---|---|---|
| default | Cleartext keyset, for local use | `ENCRYPT_KEYSET` |
| `aws` | Keyset wrapped by an AWS KMS key | `ENCRYPT_KMS_KEY_ARN`, `ENCRYPT_KMS_ENCRYPTED_KEYSET` |
| `hybrid` | HPKE public key and client-side import | `ENCRYPT_HYBRID_KEYSET` |

`.env.example` lists every variable. The service refuses to start unless exactly one of the cleartext or KMS key sources is set.

## API

All endpoints take and return JSON. Every call carries an encryption context: a tenant id and a field name. The context is bound to the ciphertext as AEAD associated data, so a ciphertext only decrypts with the exact context it was encrypted under. Copying an encrypted SSN from one tenant's record to another, or from the `ssn` field to the `email` field, makes it undecryptable.

Both parts of the context must match `[A-Za-z0-9_.-]{1,64}`. A request with a missing or invalid context is rejected with `400`.

### Encrypt

`POST /encrypt`

```bash
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"context":{"tenantId":"acme","field":"ssn"},"plaintext":"123-45-6789"}'
```

```json
{"ciphertext":"AYMGxMljOb4963+CwguDjHfkdwhGHiw/8kVeMNCYJ5gJZ55g16S+5cXZ4wA="}
```

### Decrypt

`POST /decrypt`

```bash
curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d '{"context":{"tenantId":"acme","field":"ssn"},"ciphertext":"AYMGxMljOb4963+CwguDjHfkdwhGHiw/8kVeMNCYJ5gJZ55g16S+5cXZ4wA="}'
```

```json
{"plaintext":"123-45-6789"}
```

The same ciphertext sent with `"tenantId":"globex"` or `"field":"email"` fails to decrypt with `422`.

### Re-encrypt

`POST /reencrypt` takes the same body as `/decrypt` and returns the ciphertext encrypted again under the current primary key. The plaintext never leaves the service.

```bash
curl -X POST http://localhost:8080/reencrypt \
  -H "Content-Type: application/json" \
  -d '{"context":{"tenantId":"acme","field":"ssn"},"ciphertext":"AYMGxMljOb4963+CwguDjHfkdwhGHiw/8kVeMNCYJ5gJZ55g16S+5cXZ4wA="}'
```

```json
{"ciphertext":"..."}
```

### Errors, request ids and telemetry

Every error is an RFC 9457 Problem Details body with content type `application/problem+json`.

| Status | When |
|---|---|
| `400` | Malformed JSON, a missing field, or a context outside the identifier alphabet |
| `415` | A content type other than JSON |
| `422` | A ciphertext that does not decrypt: malformed, moved to another context, or under a retired key |
| `500` | Encryption failed, or an unexpected error. The detail never carries internal exception messages |

The `422` detail is the same for every cause on purpose, so a caller cannot use the error to tell a wrong context from a retired key.

```json
{"detail":"The ciphertext is malformed, was encrypted under another context, or uses a key this service no longer holds.","instance":"/decrypt","status":422,"title":"Ciphertext rejected","requestId":"demo-2"}
```

Each request carries a request id. The service takes it from the `X-Request-Id` header when it matches `[A-Za-z0-9._-]{1,64}`, generates a UUID otherwise, echoes it in the response header and adds it to every problem body. Inside the service it travels in a `ScopedValue` (JEP 506) instead of a `ThreadLocal`. The binding ends with the request by construction, so there is no cleanup to forget, and it works the same on virtual threads, which are enabled.

Every encrypt and decrypt emits a JFR event, `dev.jaderss.encrypt.Crypto`, with its duration, operation, tenant, field, request id and outcome. Plaintext and ciphertext are never recorded.

```bash
java -XX:StartFlightRecording=filename=encrypt.jfr -jar target/encrypt-0.0.1-SNAPSHOT.jar
jfr print --events dev.jaderss.encrypt.Crypto encrypt.jfr
```

```
dev.jaderss.encrypt.Crypto {
  duration = 0,289 ms
  operation = "decrypt"
  tenantId = "globex"
  field = "ssn"
  requestId = "demo-2"
  success = false
  eventThread = "tomcat-handler-3" (javaThreadId = 59, virtual)
}
```

## Key management

### Rotation

A Tink keyset holds several keys. The primary key encrypts; every key in the set can decrypt, because each ciphertext starts with the id of the key that produced it. Rotation never breaks existing data.

1. Add a new primary key and deploy it. Existing ciphertext keeps decrypting; new ciphertext uses the new key.
   ```bash
   export ENCRYPT_KEYSET=$(scripts/keyset.sh rotate)
   ```
2. Send every stored ciphertext through `POST /reencrypt` and save the result in place of the old value.
3. Only after step 2 is complete, drop the old keys and deploy again. Any ciphertext that was not re-encrypted becomes unreadable.
   ```bash
   export ENCRYPT_KEYSET=$(scripts/keyset.sh retire)
   ```

`rotate` and `retire` read the current keyset from `ENCRYPT_KEYSET` and print the new one.

### Envelope encryption with AWS KMS

The keyset holds the data keys. In production it should never sit in an environment variable in cleartext. Under the `aws` profile the service takes the keyset wrapped by an AWS KMS key, the key-encryption key, and asks KMS to unwrap it once at startup. Requests never call KMS, and the data keys never exist outside the process in cleartext.

```bash
export ENCRYPT_KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:key/...
export ENCRYPT_KMS_ENCRYPTED_KEYSET=$(scripts/keyset.sh new)
SPRING_PROFILES_ACTIVE=aws ./mvnw spring-boot:run
```

With `ENCRYPT_KMS_KEY_ARN` set, `scripts/keyset.sh new|rotate|retire` reads `ENCRYPT_KMS_ENCRYPTED_KEYSET` and prints a wrapped keyset, so the cleartext keyset is never printed. The wrapped keyset is bound to the label `tink-encrypt/keyset/v1` as associated data. AWS credentials and region come from the standard AWS SDK chain. The service needs `kms:Decrypt` on the key, and the operator running the script needs `kms:Encrypt` too.

The default profile keeps the cleartext `ENCRYPT_KEYSET` for local development. Setting both key sources, or neither, stops startup.

Tink also offers `KmsEnvelopeAead`, which asks KMS for a new data key on every encryption. That isolates every message but adds a KMS call, with its latency and cost, to each request. Wrapping the keyset gives one KMS call per start, which suits a service that encrypts on every request.

`KmsKeysetIntegrationTest` runs this path against LocalStack through Testcontainers, so the build needs Docker. It is pinned to `localstack/localstack:4.14.0`, the last LocalStack release that runs without an auth token.

## Hybrid encryption for client-side encryption

Some values should be encrypted before they reach the service, for example an SSN typed into a browser. Under the `hybrid` profile the service publishes an HPKE public key (X25519, HKDF-SHA256, AES-256-GCM). A client encrypts to it, and the service converts the result into its normal context-bound storage ciphertext. The plaintext is never returned over HTTP.

```bash
export ENCRYPT_HYBRID_KEYSET=$(scripts/keyset.sh new-hybrid)
SPRING_PROFILES_ACTIVE=hybrid ./mvnw spring-boot:run
```

- `GET /hybrid/public-key` returns `{"publicKeyset":"..."}`, a Tink public keyset with no private key in it.
- `POST /hybrid/import` takes `{"context":{...},"ciphertext":"<base64 HPKE ciphertext>"}` and returns `{"ciphertext":"..."}`, the same format `/encrypt` produces.

The client must pass `tenantId:field` in UTF-8 as the HPKE context info, matching the request's `context`. A value encrypted for `acme:email` fails to import as `acme:ssn`. Without the `hybrid` profile the two endpoints do not exist.

### Public key as PEM (Java 25 preview)

`PublicKeyPem` exports the X25519 public key as a standard `-----BEGIN PUBLIC KEY-----` block with the PEM API from JEP 470. That API is a preview feature in Java 25, so the code lives in `src/preview/java` and only compiles under its own Maven profile, with output in `target/preview`. The main build and the application jar never depend on a preview feature.

```bash
ENCRYPT_HYBRID_KEYSET=... scripts/public-key-pem.sh
./mvnw verify -Ppem-preview
```

OpenSSL reads the result as an `X25519 Public-Key`. PEM helps a client that does not use Tink. Such a client implements RFC 9180 itself and must put Tink's 5-byte key prefix (`0x01` and the key id) in front of its ciphertext, because the keyset uses Tink's `TINK` output variant.

## Per-tenant keys with the Java 25 KDF API

`TenantKeyDerivation` derives a separate AES-256-GCM key for each tenant from one master secret, using HKDF-SHA256 through `javax.crypto.KDF`, the key derivation API that became final in Java 25 (JEP 510).

- Input key material: the master secret, at least 32 bytes.
- Salt: random bytes chosen once per deployment and stored next to the master secret.
- Info: `tink-encrypt/tenant-data-key/v1`, a zero byte, then the tenant id. The version in the label lets a future scheme derive different keys from the same secret.
- Output: 32 bytes, imported into Tink as an AES-GCM key and returned as an `Aead`.

The same inputs always produce the same key, so no per-tenant key is stored anywhere. A test checks the HKDF wiring against test case 1 of RFC 5869, so swapping salt and key material, an easy mistake with this API, fails the build.

The trade-offs are real. Losing the master secret loses every tenant. You cannot destroy one tenant's key to make their data unreadable without changing the master secret for everyone. Use stored per-tenant keysets if you need per-tenant crypto-shredding.

This component is not on the HTTP path. The endpoints keep using the Tink keyset from `ENCRYPT_KEYSET`.

### JDK KDF or Tink key derivation

Tink has its own derivation primitive, `KeysetDeriver`, built on a PRF-based key derivation keyset. It returns a complete Tink keyset for a given salt.

| | `javax.crypto.KDF` (JDK 25) | Tink `KeysetDeriver` |
|---|---|---|
| Master secret | Raw bytes you store and protect yourself | A Tink keyset, stored and rotated like any other |
| Output | Bytes or a `SecretKey`; you pick the cipher and the format | A `KeysetHandle` with key ids and Tink's ciphertext format |
| Rotation | Version the info label or the master secret by hand | Normal keyset rotation |
| Interoperability | Standard RFC 5869; any language with HKDF reproduces the key | Tink's own scheme; reproducible from Tink in other languages |
| Dependency | None beyond the JDK | Tink |

Use the JDK API when the derived key has to match a system outside Tink, when a protocol specifies HKDF directly, or when you want no crypto library at all. Use Tink's `KeysetDeriver` when the derived keys stay inside Tink, because you get key ids, rotation and Tink's safe defaults without writing the glue code this component needs.

## Modern Java features and why they are here

| Feature | JEP | Since | Where | Why |
|---|---|---|---|---|
| Key Derivation Function API | 510 | 25 | `kdf/TenantKeyDerivation` | HKDF from the JDK, with no extra library, for per-tenant keys |
| Scoped values | 506 | 25 | `request/RequestContext` | Request id without a `ThreadLocal`, so nothing leaks between requests or needs cleanup |
| AOT cache with one-step training | 514, 515 | 25 | `scripts/startup-benchmark.sh` | Startup in about a third of the fat jar's time |
| PEM encodings (preview) | 470 | 25, preview | `src/preview`, `-Ppem-preview` | Standard PEM for the hybrid public key, kept out of the main build |
| Virtual threads | 444 | 21 | `spring.threads.virtual.enabled` | Request threads that cost almost nothing while a request blocks |
| Records and pattern matching for `instanceof` | 395, 394 | 16 | Request and response types, `EncryptionContext`, `PublicKeyPem` | Immutable values that validate themselves when created |

## Startup with the AOT cache

Java 25 can build an ahead-of-time cache in one training run (JEP 514): `-XX:AOTCacheOutput` records which classes the application loads and links, and since JEP 515 also the method profiles gathered during that run. Later runs start from the cache instead of loading and linking those classes again.

`scripts/startup-benchmark.sh` measures this. It builds the jar, extracts it with Spring Boot's `jarmode=tools` (a cache cannot map classes from nested fat-jar entries), trains the cache with `-Dspring.context.exit=onRefresh`, then starts each configuration ten times after one discarded warm-up and reports the median of the times Spring Boot logs. The AOT run uses `-XX:AOTMode=on`, so it fails rather than silently starting without the cache.

Measured on 2026-10-20, Apple M4 Max, Temurin 25.0.4.1, Spring Boot 4.1.1, default profile:

| Configuration | Context started | Process ready |
|---|---|---|
| Fat jar | 0.769 s | 0.967 s |
| Extracted jar | 0.607 s | 0.728 s |
| Extracted jar with AOT cache | 0.256 s | 0.338 s |

A second full run landed within 1% of these numbers. With the cache the process is ready in about a third of the fat jar's time, and in less than half of the extracted jar's. The cache is 61 MB.

What these numbers do not show: the training run stops once the context is refreshed, so the profiles cover startup only, not request handling, and nothing here measures throughput or peak performance. The cache is tied to the exact jar and JDK that built it and has to be regenerated whenever either changes, which belongs in the image build, not on a developer machine.

```bash
scripts/startup-benchmark.sh
RUNS=20 scripts/startup-benchmark.sh
```

## Build and test

```bash
./mvnw verify
./mvnw verify -Ppem-preview
./mvnw spotless:apply
```

`verify` runs the tests, including the LocalStack ones, and fails on formatting that does not match Palantir Java Format. GitHub Actions runs both builds and a gitleaks scan of the full history on every push.

| Script | Does |
|---|---|
| `scripts/keyset.sh new\|rotate\|retire` | Creates and rotates the AEAD keyset; wraps it with KMS when `ENCRYPT_KMS_KEY_ARN` is set |
| `scripts/keyset.sh new-hybrid\|public-key` | Creates the hybrid keyset and prints its public half |
| `scripts/public-key-pem.sh` | Prints the hybrid public key as PEM |
| `scripts/startup-benchmark.sh` | Measures startup with and without the AOT cache |

## Layout

```
src/main/java/dev/jaderss/encrypt/
  config/      key sources, KMS client, validated properties
  controller/  REST endpoints, request and response records, Problem Details
  service/     encryption, context binding, hybrid import, JFR event
  keyset/      keyset generation, rotation, retirement, KMS wrapping
  kdf/         per-tenant key derivation with the KDF API
  request/     request id filter and ScopedValue
src/preview/java/   PEM export, built only with -Ppem-preview
```

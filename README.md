# Encrypt API

A Spring Boot REST API service for text encryption and decryption using Google Tink cryptography library with AES256-GCM encryption.

## Features

- **Text Encryption**: Encrypt plain text using AES256-GCM algorithm
- **Text Decryption**: Decrypt encrypted text back to plain text
- **Context binding**: Ciphertext is bound to a tenant and field and fails to decrypt anywhere else
- **Key rotation**: New primary keys without breaking existing ciphertext, plus a re-encrypt endpoint
- **Per-tenant key derivation**: HKDF through the Java 25 KDF API
- **Envelope encryption**: Keyset wrapped by an AWS KMS key under the `aws` profile
- **Hybrid encryption**: HPKE public key for client-side encryption, exportable as PEM
- **Fast startup**: Measured startup with the Java 25 AOT cache
- **Secure**: Uses Google Tink cryptography library for robust security
- **RESTful API**: Simple HTTP endpoints for easy integration
- **Base64 Encoding**: All encrypted data is Base64 encoded for safe transmission

## Technology Stack

- **Java 25**
- **Spring Boot 4.1**
- **Google Tink 1.24** (Cryptography library)
- **Maven** (Build tool, wrapper included)
- **Spotless** with Palantir Java Format

## Prerequisites

- Java 25
- Docker, for the LocalStack tests

## Installation & Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd encrypt
   ```

2. **Build the project**
   ```bash
   ./mvnw clean install
   ```

3. **Run the application**
   ```bash
   ./mvnw spring-boot:run
   ```

The application will start on `http://localhost:8080`

## Configuration

The service reads a base64 Tink keyset from the `ENCRYPT_KEYSET` environment variable. It refuses to start without one. No keyset is committed to the repository.

```bash
export ENCRYPT_KEYSET=$(scripts/keyset.sh new)
./mvnw spring-boot:run
```

`.env.example` lists the variable. Tests generate their own keyset and need no setup.

## API Endpoints

Both endpoints take and return JSON. Every call carries an encryption context: a tenant id and a field name. The context is bound to the ciphertext as AEAD associated data, so a ciphertext only decrypts with the exact context it was encrypted under. Copying an encrypted SSN from one tenant's record to another, or from the `ssn` field to the `email` field, makes it undecryptable.

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

## Errors, request ids and telemetry

Every error is an RFC 9457 Problem Details body with content type `application/problem+json`.

| Status | When |
|---|---|
| `400` | Malformed JSON, a missing field, or a context outside the identifier alphabet |
| `415` | A content type other than JSON |
| `422` | A ciphertext that does not decrypt: malformed, moved to another context, or under a retired key |
| `500` | Encryption itself failed |

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

## Key rotation

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

## Envelope encryption with AWS KMS

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

## Testing

The project includes sample HTTP requests in `http/sample.http` that can be used with HTTP clients like IntelliJ IDEA, VS Code REST Client, or similar tools.

### Running Tests
```bash
./mvnw test
```

## Security Considerations

- **Key Management**: The keyset comes from the `ENCRYPT_KEYSET` environment variable and is created and rotated offline with `scripts/keyset.sh`. The service never generates or returns keys over HTTP.
- **HTTPS**: Always use HTTPS in production to protect data in transit.
- **Key Rotation**: See [Key rotation](#key-rotation). Old keys stay until every ciphertext is re-encrypted.
- **Access Control**: Implement proper authentication and authorization for the API endpoints.

## Project Structure

```
src/
├── main/
│   ├── java/dev/jaderss/encrypt/
│   │   ├── EncryptApplication.java          # Main Spring Boot application
│   │   ├── config/
│   │   │   └── SecurityConfig.java         # Security configuration
│   │   ├── controller/
│   │   │   └── SecurityController.java     # REST API endpoints
│   │   └── service/
│   │       └── SecurityService.java        # Encryption/decryption logic
│   └── resources/
│       └── application.yml                 # Application configuration
├── test/
│   └── java/dev/jaderss/encrypt/
│       └── EncryptApplicationTests.java    # Unit tests
└── http/
    └── sample.http                         # Sample HTTP requests
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

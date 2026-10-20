# Encrypt API

A Spring Boot REST API service for text encryption and decryption using Google Tink cryptography library with AES256-GCM encryption.

## Features

- **Text Encryption**: Encrypt plain text using AES256-GCM algorithm
- **Text Decryption**: Decrypt encrypted text back to plain text
- **Context binding**: Ciphertext is bound to a tenant and field and fails to decrypt anywhere else
- **Key rotation**: New primary keys without breaking existing ciphertext, plus a re-encrypt endpoint
- **Per-tenant key derivation**: HKDF through the Java 25 KDF API
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

The same ciphertext sent with `"tenantId":"globex"` or `"field":"email"` fails to decrypt.

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

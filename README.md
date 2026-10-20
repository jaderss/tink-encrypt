# Encrypt API

A Spring Boot REST API service for text encryption and decryption using Google Tink cryptography library with AES256-GCM encryption.

## Features

- **Text Encryption**: Encrypt plain text using AES256-GCM algorithm
- **Text Decryption**: Decrypt encrypted text back to plain text
- **Context binding**: Ciphertext is bound to a tenant and field and fails to decrypt anywhere else
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
export ENCRYPT_KEYSET=$(scripts/new-keyset.sh)
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

## Testing

The project includes sample HTTP requests in `http/sample.http` that can be used with HTTP clients like IntelliJ IDEA, VS Code REST Client, or similar tools.

### Running Tests
```bash
./mvnw test
```

## Security Considerations

- **Key Management**: The keyset comes from the `ENCRYPT_KEYSET` environment variable and is created offline with `scripts/new-keyset.sh`. The service never generates or returns keys over HTTP.
- **HTTPS**: Always use HTTPS in production to protect data in transit.
- **Key Rotation**: Regularly rotate encryption keys for enhanced security.
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

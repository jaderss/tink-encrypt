# Encrypt API

A Spring Boot REST API service for text encryption and decryption using Google Tink cryptography library with AES256-GCM encryption.

## Features

- **Text Encryption**: Encrypt plain text using AES256-GCM algorithm
- **Text Decryption**: Decrypt encrypted text back to plain text
- **Key Generation**: Generate new encryption keys dynamically
- **Secure**: Uses Google Tink cryptography library for robust security
- **RESTful API**: Simple HTTP endpoints for easy integration
- **Base64 Encoding**: All encrypted data is Base64 encoded for safe transmission

## Technology Stack

- **Java 24**
- **Spring Boot 3.5.3**
- **Google Tink 1.18.0** (Cryptography library)
- **Maven** (Build tool)
- **Lombok** (Code generation)

## Prerequisites

- Java 24 or higher
- Maven 3.6+ 

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

The application uses a pre-configured encryption key in `src/main/resources/application.yml`:

```yaml
spring:
  application:
    name: encrypt

encrypt:
  key: CInTwbMDEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIMhYGGgFwmnfeKhspGvTr2SneK6N4yhNCJUMKIi5C1cCGAEQARiJ08GzAyAB
```

### Generating New Keys

You can generate a new encryption key using either:

1. **API Endpoint** (recommended for runtime):
   ```bash
   curl -X POST http://localhost:8080/key/generate
   ```

## API Endpoints

### 1. Encrypt Text
**Endpoint**: `POST /encrypt`  
**Content-Type**: `text/plain`  
**Description**: Encrypts plain text and returns Base64 encoded ciphertext

**Example Request**:
```bash
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: text/plain" \
  -d "Hello World!"
```

**Example Response**:
```
ATZwaYkDzds0ltoZ3WuPFVF0/bvdufgvnK6fapQwWe2iv2GK+m+nPiuj3/q4
```

### 2. Decrypt Text
**Endpoint**: `POST /decrypt`  
**Content-Type**: `text/plain`  
**Description**: Decrypts Base64 encoded ciphertext back to plain text

**Example Request**:
```bash
curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: text/plain" \
  -d "ATZwaYkDzds0ltoZ3WuPFVF0/bvdufgvnK6fapQwWe2iv2GK+m+nPiuj3/q4"
```

**Example Response**:
```
Hello World!
```

### 3. Generate New Key
**Endpoint**: `POST /key/generate`  
**Content-Type**: `text/plain`  
**Description**: Generates a new AES256-GCM encryption key

**Example Request**:
```bash
curl -X POST http://localhost:8080/key/generate
```

**Example Response**:
```
CInTwbMDEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIMhYGGgFwmnfeKhspGvTr2SneK6N4yhNCJUMKIi5C1cCGAEQARiJ08GzAyAB
```

## Testing

The project includes sample HTTP requests in `http/sample.http` that can be used with HTTP clients like IntelliJ IDEA, VS Code REST Client, or similar tools.

### Running Tests
```bash
./mvnw test
```

## Security Considerations

- **Key Management**: The encryption key is stored in the application configuration. For production use, consider using environment variables or a secure key management service.
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

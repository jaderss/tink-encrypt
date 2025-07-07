package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.SecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Slf4j
@RestController
@RequestMapping("/")
@RequiredArgsConstructor
public class SecurityController {

    private final SecurityService securityService;

    @PostMapping(value = "/encrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> encrypt(@RequestBody(required = false) String plainText) {
        try {
            if (plainText == null) {
                return ResponseEntity.badRequest().build();
            }
            String encryptedText = securityService.encrypt(plainText.trim());
            return ResponseEntity.ok(encryptedText);
        } catch (GeneralSecurityException e) {
            log.error("Encryption failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping(value = "/decrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> decrypt(@RequestBody(required = false) String encrypted) {
        try {
            if (encrypted == null) {
                return ResponseEntity.badRequest().build();
            }
            String decryptedText = securityService.decrypt(encrypted.trim());
            return ResponseEntity.ok(decryptedText);
        } catch (GeneralSecurityException e) {
            log.error("Decryption failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping(value = "/key/generate", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> generateKey() {
        try {
            return ResponseEntity.ok(securityService.generateKey());
        } catch (GeneralSecurityException | IOException e) {
            log.error("Key generation failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}

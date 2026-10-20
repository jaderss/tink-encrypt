package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.SecurityService;
import java.security.GeneralSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class SecurityController {

    private static final Logger log = LoggerFactory.getLogger(SecurityController.class);

    private final SecurityService securityService;

    public SecurityController(SecurityService securityService) {
        this.securityService = securityService;
    }

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
}

package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.SecurityService;
import java.security.GeneralSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    private static final Logger log = LoggerFactory.getLogger(SecurityController.class);

    private final SecurityService securityService;

    public SecurityController(SecurityService securityService) {
        this.securityService = securityService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<CiphertextResponse> encrypt(@RequestBody PlaintextRequest request) {
        try {
            return ResponseEntity.ok(
                    new CiphertextResponse(securityService.encrypt(request.context(), request.plaintext())));
        } catch (GeneralSecurityException e) {
            log.error("Encryption failed", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<PlaintextResponse> decrypt(@RequestBody CiphertextRequest request) {
        try {
            return ResponseEntity.ok(
                    new PlaintextResponse(securityService.decrypt(request.context(), request.ciphertext())));
        } catch (GeneralSecurityException e) {
            log.error("Decryption failed", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/reencrypt")
    public ResponseEntity<CiphertextResponse> reencrypt(@RequestBody CiphertextRequest request) {
        try {
            return ResponseEntity.ok(
                    new CiphertextResponse(securityService.reencrypt(request.context(), request.ciphertext())));
        } catch (GeneralSecurityException e) {
            log.error("Re-encryption failed", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}

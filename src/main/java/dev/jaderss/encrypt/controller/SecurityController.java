package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.SecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody String plainText) throws GeneralSecurityException {
        String decryptedText = securityService.encrypt(plainText.trim());
        return ResponseEntity.ok(decryptedText);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody String encrypted) throws GeneralSecurityException {
            String decryptedText = securityService.decrypt(encrypted.trim());
            return ResponseEntity.ok(decryptedText);
    }

    @PostMapping("/key/generate")
    public ResponseEntity<String> generateKey() throws GeneralSecurityException, IOException {
        return ResponseEntity.ok(securityService.generateKey());
    }
}
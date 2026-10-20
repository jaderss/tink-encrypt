package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.SecurityService;
import java.security.GeneralSecurityException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    private final SecurityService securityService;

    public SecurityController(SecurityService securityService) {
        this.securityService = securityService;
    }

    @PostMapping("/encrypt")
    public CiphertextResponse encrypt(@RequestBody PlaintextRequest request) throws GeneralSecurityException {
        return new CiphertextResponse(securityService.encrypt(request.context(), request.plaintext()));
    }

    @PostMapping("/decrypt")
    public PlaintextResponse decrypt(@RequestBody CiphertextRequest request) {
        return new PlaintextResponse(securityService.decrypt(request.context(), request.ciphertext()));
    }

    @PostMapping("/reencrypt")
    public CiphertextResponse reencrypt(@RequestBody CiphertextRequest request) throws GeneralSecurityException {
        return new CiphertextResponse(securityService.reencrypt(request.context(), request.ciphertext()));
    }
}

package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.HybridImportService;
import java.security.GeneralSecurityException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hybrid")
@ConditionalOnProperty(prefix = "encrypt", name = "hybrid-keyset")
public class HybridController {

    private final HybridImportService hybridImportService;

    public HybridController(HybridImportService hybridImportService) {
        this.hybridImportService = hybridImportService;
    }

    @GetMapping("/public-key")
    public PublicKeysetResponse publicKey() {
        return new PublicKeysetResponse(hybridImportService.publicKeyset());
    }

    @PostMapping("/import")
    public CiphertextResponse importCiphertext(@RequestBody CiphertextRequest request) throws GeneralSecurityException {
        return new CiphertextResponse(hybridImportService.importCiphertext(request.context(), request.ciphertext()));
    }
}

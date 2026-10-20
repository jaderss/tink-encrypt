package dev.jaderss.encrypt.service;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeysetHandle;
import dev.jaderss.encrypt.keyset.Keysets;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;

public class HybridImportService {

    private final HybridDecrypt hybridDecrypt;
    private final String publicKeyset;
    private final SecurityService securityService;

    public HybridImportService(KeysetHandle hybridKeyset, SecurityService securityService)
            throws GeneralSecurityException {
        this.hybridDecrypt = hybridKeyset.getPrimitive(HybridDecrypt.class);
        this.publicKeyset = Keysets.encodePublic(hybridKeyset.getPublicKeysetHandle());
        this.securityService = securityService;
    }

    public String publicKeyset() {
        return publicKeyset;
    }

    public String importCiphertext(EncryptionContext context, String hybridCiphertext) throws GeneralSecurityException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(hybridCiphertext, "hybridCiphertext");
        byte[] plaintext =
                hybridDecrypt.decrypt(Base64.getDecoder().decode(hybridCiphertext), context.associatedData());
        return securityService.encrypt(context, new String(plaintext, StandardCharsets.UTF_8));
    }
}

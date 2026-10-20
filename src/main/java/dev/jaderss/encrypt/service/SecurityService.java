package dev.jaderss.encrypt.service;

import com.google.crypto.tink.Aead;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import org.springframework.stereotype.Service;

@Service
public class SecurityService {

    private final Aead aead;

    public SecurityService(Aead aead) {
        this.aead = aead;
    }

    public String encrypt(EncryptionContext context, String plaintext) throws GeneralSecurityException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(plaintext, "plaintext");
        byte[] ciphertext = aead.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), context.associatedData());
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(EncryptionContext context, String ciphertext) throws GeneralSecurityException {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(ciphertext, "ciphertext");
        byte[] plaintext = aead.decrypt(Base64.getDecoder().decode(ciphertext), context.associatedData());
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}

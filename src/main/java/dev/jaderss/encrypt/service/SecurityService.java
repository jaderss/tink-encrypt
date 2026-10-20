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
        CryptoEvent event = new CryptoEvent("encrypt", context);
        event.begin();
        try {
            byte[] ciphertext = aead.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), context.associatedData());
            event.success = true;
            return Base64.getEncoder().encodeToString(ciphertext);
        } finally {
            event.commit();
        }
    }

    public String decrypt(EncryptionContext context, String ciphertext) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(ciphertext, "ciphertext");
        CryptoEvent event = new CryptoEvent("decrypt", context);
        event.begin();
        try {
            byte[] plaintext = aead.decrypt(Base64.getDecoder().decode(ciphertext), context.associatedData());
            event.success = true;
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CiphertextRejectedException(e);
        } finally {
            event.commit();
        }
    }

    public String reencrypt(EncryptionContext context, String ciphertext) throws GeneralSecurityException {
        return encrypt(context, decrypt(context, ciphertext));
    }
}

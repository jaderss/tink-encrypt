package dev.jaderss.encrypt.service;

import com.google.crypto.tink.Aead;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.springframework.stereotype.Service;

@Service
public class SecurityService {

    private final Aead aead;

    public SecurityService(Aead aead) {
        this.aead = aead;
    }

    public String encrypt(final String plaintext) throws GeneralSecurityException {
        byte[] ciphertext = aead.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), new byte[0]);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(final String ciphertext) throws GeneralSecurityException {
        byte[] decrypted = aead.decrypt(Base64.getDecoder().decode(ciphertext), new byte[0]);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}

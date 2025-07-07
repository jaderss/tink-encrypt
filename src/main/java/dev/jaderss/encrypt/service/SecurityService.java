package dev.jaderss.encrypt.service;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityService {

    private final KeysetHandle keysetHandle;

    public String encrypt(final String plaintext) throws GeneralSecurityException {
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        byte[] ciphertext = aead.encrypt(plaintext.getBytes(StandardCharsets.UTF_8), new byte[0]);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String decrypt(final String ciphertext) throws GeneralSecurityException {
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        byte[] decrypted = aead.decrypt(Base64.getDecoder().decode(ciphertext), new byte[0]);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public String generateKey() throws GeneralSecurityException, IOException {
        AeadConfig.register();
        KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CleartextKeysetHandle.write(handle, BinaryKeysetWriter.withOutputStream(outputStream));
        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }
}
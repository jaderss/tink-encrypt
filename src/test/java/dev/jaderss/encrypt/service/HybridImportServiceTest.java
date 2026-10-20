package dev.jaderss.encrypt.service;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import dev.jaderss.encrypt.keyset.Keysets;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class HybridImportServiceTest {

    private final SecurityService securityService;
    private final HybridImportService hybridImportService;
    private final HybridEncrypt client;

    HybridImportServiceTest() throws GeneralSecurityException {
        securityService = new SecurityService(Keysets.parse(Keysets.generate()).getPrimitive(Aead.class));
        hybridImportService = new HybridImportService(Keysets.parse(Keysets.generateHybrid()), securityService);
        client = TinkProtoKeysetFormat.parseKeysetWithoutSecret(
                        Base64.getDecoder().decode(hybridImportService.publicKeyset()))
                .getPrimitive(HybridEncrypt.class);
    }

    @Test
    void importTurnsClientCiphertextIntoStorageCiphertext() throws GeneralSecurityException {
        String stored = hybridImportService.importCiphertext(CONTEXT, clientEncrypt("123-45-6789", "acme:ssn"));

        assertThat(securityService.decrypt(CONTEXT, stored)).isEqualTo("123-45-6789");
    }

    @Test
    void importRejectsClientCiphertextMadeForAnotherField() throws GeneralSecurityException {
        String forEmailField = clientEncrypt("123-45-6789", "acme:email");

        assertThatThrownBy(() -> hybridImportService.importCiphertext(CONTEXT, forEmailField))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void publishedKeysetHoldsNoPrivateKey() {
        byte[] published = Base64.getDecoder().decode(hybridImportService.publicKeyset());

        assertThatCode(() -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(published))
                .doesNotThrowAnyException();
    }

    private String clientEncrypt(String plaintext, String contextInfo) throws GeneralSecurityException {
        byte[] ciphertext = client.encrypt(
                plaintext.getBytes(StandardCharsets.UTF_8), contextInfo.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ciphertext);
    }
}

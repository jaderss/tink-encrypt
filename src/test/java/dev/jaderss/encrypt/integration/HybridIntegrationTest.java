package dev.jaderss.encrypt.integration;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import dev.jaderss.encrypt.TestKeysetConfig;
import dev.jaderss.encrypt.controller.CiphertextRequest;
import dev.jaderss.encrypt.controller.CiphertextResponse;
import dev.jaderss.encrypt.controller.PlaintextResponse;
import dev.jaderss.encrypt.controller.PublicKeysetResponse;
import dev.jaderss.encrypt.keyset.Keysets;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestKeysetConfig.class)
class HybridIntegrationTest {

    private final RestClient client;

    HybridIntegrationTest(@LocalServerPort int port) {
        client = RestClient.create("http://localhost:" + port);
    }

    @DynamicPropertySource
    static void hybridKeyset(DynamicPropertyRegistry registry) throws GeneralSecurityException {
        String hybridKeyset = Keysets.generateHybrid();
        registry.add("encrypt.hybrid-keyset", () -> hybridKeyset);
    }

    @Test
    void clientEncryptsToPublishedKeyAndServiceStoresItUnderContext() throws GeneralSecurityException {
        String publicKeyset = client.get()
                .uri("/hybrid/public-key")
                .retrieve()
                .body(PublicKeysetResponse.class)
                .publicKeyset();
        HybridEncrypt encrypter = TinkProtoKeysetFormat.parseKeysetWithoutSecret(
                        Base64.getDecoder().decode(publicKeyset))
                .getPrimitive(HybridEncrypt.class);
        String hybridCiphertext = Base64.getEncoder()
                .encodeToString(encrypter.encrypt(
                        "123-45-6789".getBytes(StandardCharsets.UTF_8), "acme:ssn".getBytes(StandardCharsets.UTF_8)));

        String stored = post(
                        "/hybrid/import", new CiphertextRequest(CONTEXT, hybridCiphertext), CiphertextResponse.class)
                .ciphertext();

        assertThat(post("/decrypt", new CiphertextRequest(CONTEXT, stored), PlaintextResponse.class))
                .isEqualTo(new PlaintextResponse("123-45-6789"));
    }

    private <T> T post(String path, Object request, Class<T> responseType) {
        return client.post()
                .uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(responseType);
    }
}

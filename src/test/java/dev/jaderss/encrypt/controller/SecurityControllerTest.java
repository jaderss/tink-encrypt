package dev.jaderss.encrypt.controller;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verifyNoInteractions;

import dev.jaderss.encrypt.service.SecurityService;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.assertj.MockMvcTester.MockMvcRequestBuilder;
import tools.jackson.databind.json.JsonMapper;

@WebMvcTest(SecurityController.class)
class SecurityControllerTest {

    private static final String CIPHERTEXT = "ciphertext-from-service";

    @Autowired
    private MockMvcTester mvc;

    @Autowired
    private JsonMapper jsonMapper;

    @MockitoBean
    private SecurityService securityService;

    @ParameterizedTest
    @MethodSource("dev.jaderss.encrypt.Samples#plaintexts")
    void encryptReturnsCiphertextForContextAndPlaintext(String plaintext) throws Exception {
        given(securityService.encrypt(CONTEXT, plaintext)).willReturn(CIPHERTEXT);

        assertThat(postJson("/encrypt", new PlaintextRequest(CONTEXT, plaintext)))
                .hasStatusOk()
                .bodyJson()
                .extractingPath("$.ciphertext")
                .isEqualTo(CIPHERTEXT);
    }

    @Test
    void decryptReturnsPlaintextForContextAndCiphertext() throws Exception {
        given(securityService.decrypt(CONTEXT, CIPHERTEXT)).willReturn("Hello World!");

        assertThat(postJson("/decrypt", new CiphertextRequest(CONTEXT, CIPHERTEXT)))
                .hasStatusOk()
                .bodyJson()
                .extractingPath("$.plaintext")
                .isEqualTo("Hello World!");
    }

    @Test
    void reencryptReturnsCiphertextUnderCurrentKey() throws Exception {
        given(securityService.reencrypt(CONTEXT, CIPHERTEXT)).willReturn("ciphertext-under-new-key");

        assertThat(postJson("/reencrypt", new CiphertextRequest(CONTEXT, CIPHERTEXT)))
                .hasStatusOk()
                .bodyJson()
                .extractingPath("$.ciphertext")
                .isEqualTo("ciphertext-under-new-key");
    }

    @Test
    void encryptReturnsServerErrorWhenEncryptionFails() throws Exception {
        given(securityService.encrypt(any(), any())).willThrow(new GeneralSecurityException("encrypt failed"));

        assertThat(postJson("/encrypt", new PlaintextRequest(CONTEXT, "Hello World!")))
                .hasStatus(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void decryptReturnsServerErrorWhenDecryptionFails() throws Exception {
        given(securityService.decrypt(any(), any())).willThrow(new GeneralSecurityException("decrypt failed"));

        assertThat(postJson("/decrypt", new CiphertextRequest(CONTEXT, CIPHERTEXT)))
                .hasStatus(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "",
                "{\"plaintext\":\"Hello\"}",
                "{\"context\":{\"tenantId\":\"acme\",\"field\":\"ssn\"}}",
                "{\"context\":{\"tenantId\":\"acme:ssn\",\"field\":\"x\"},\"plaintext\":\"Hello\"}",
                "{\"context\":{\"tenantId\":\"acme\"},\"plaintext\":\"Hello\"}"
            })
    void encryptRejectsIncompleteOrInvalidRequestWithoutCallingService(String body) {
        assertThat(mvc.post()
                        .uri("/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .hasStatus(HttpStatus.BAD_REQUEST);
        verifyNoInteractions(securityService);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/encrypt", "/decrypt", "/reencrypt"})
    void rejectsPlainTextContentTypeWithoutCallingService(String path) {
        assertThat(mvc.post().uri(path).contentType(MediaType.TEXT_PLAIN).content("Hello"))
                .hasStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        verifyNoInteractions(securityService);
    }

    private MockMvcRequestBuilder postJson(String path, Object request) {
        return mvc.post()
                .uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonMapper.writeValueAsString(request));
    }
}

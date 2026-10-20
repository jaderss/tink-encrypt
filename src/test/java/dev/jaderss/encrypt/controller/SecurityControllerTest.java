package dev.jaderss.encrypt.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
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

@WebMvcTest(SecurityController.class)
class SecurityControllerTest {

    private static final String CIPHERTEXT = "ciphertext-from-service";

    @Autowired
    private MockMvcTester mvc;

    @MockitoBean
    private SecurityService securityService;

    @ParameterizedTest
    @MethodSource("dev.jaderss.encrypt.SamplePlaintexts#nonEmpty")
    void encryptReturnsCiphertextFromService(String plaintext) throws Exception {
        given(securityService.encrypt(plaintext)).willReturn(CIPHERTEXT);

        assertThat(postText("/encrypt", plaintext)).hasStatusOk().bodyText().isEqualTo(CIPHERTEXT);
    }

    @Test
    void encryptTrimsPlaintextBeforeEncrypting() throws Exception {
        given(securityService.encrypt("Hello World!")).willReturn(CIPHERTEXT);

        assertThat(postText("/encrypt", "  Hello World!  "))
                .hasStatusOk()
                .bodyText()
                .isEqualTo(CIPHERTEXT);
    }

    @Test
    void decryptReturnsPlaintextFromService() throws Exception {
        given(securityService.decrypt(CIPHERTEXT)).willReturn("Hello World!");

        assertThat(postText("/decrypt", CIPHERTEXT)).hasStatusOk().bodyText().isEqualTo("Hello World!");
    }

    @Test
    void decryptTrimsCiphertextBeforeDecrypting() throws Exception {
        given(securityService.decrypt(CIPHERTEXT)).willReturn("Hello World!");

        assertThat(postText("/decrypt", "  " + CIPHERTEXT + "  "))
                .hasStatusOk()
                .bodyText()
                .isEqualTo("Hello World!");
    }

    @ParameterizedTest
    @ValueSource(strings = {"/encrypt", "/decrypt"})
    void returnsServerErrorWhenCryptoFails(String path) throws Exception {
        given(securityService.encrypt(anyString())).willThrow(new GeneralSecurityException("encrypt failed"));
        given(securityService.decrypt(anyString())).willThrow(new GeneralSecurityException("decrypt failed"));

        assertThat(postText(path, "payload")).hasStatus(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/encrypt", "/decrypt"})
    void rejectsMissingBodyWithoutCallingService(String path) {
        assertThat(mvc.post().uri(path).contentType(MediaType.TEXT_PLAIN)).hasStatus(HttpStatus.BAD_REQUEST);
        verifyNoInteractions(securityService);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/encrypt", "/decrypt"})
    void rejectsJsonContentTypeWithoutCallingService(String path) {
        assertThat(mvc.post().uri(path).contentType(MediaType.APPLICATION_JSON).content("{\"text\":\"Hello\"}"))
                .hasStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        verifyNoInteractions(securityService);
    }

    private MockMvcRequestBuilder postText(String path, String body) {
        return mvc.post().uri(path).contentType(MediaType.TEXT_PLAIN).content(body);
    }
}

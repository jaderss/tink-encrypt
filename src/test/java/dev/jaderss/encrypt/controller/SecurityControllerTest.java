package dev.jaderss.encrypt.controller;

import dev.jaderss.encrypt.service.SecurityService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(SecurityController.class)
class SecurityControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SecurityService securityService;

    @Test
    void encrypt_ShouldReturnEncryptedText_WhenGivenValidPlaintext() throws Exception {
        // Given
        String plaintext = "Hello World!";
        String expectedEncrypted = "encrypted-base64-string";
        when(securityService.encrypt(plaintext)).thenReturn(expectedEncrypted);

        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(plaintext))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedEncrypted));

        verify(securityService).encrypt(plaintext);
    }

    @Test
    void encrypt_ShouldTrimInputAndReturnEncryptedText() throws Exception {
        // Given
        String plaintextWithSpaces = "  Hello World!  ";
        String trimmedPlaintext = "Hello World!";
        String expectedEncrypted = "encrypted-base64-string";
        when(securityService.encrypt(trimmedPlaintext)).thenReturn(expectedEncrypted);

        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(plaintextWithSpaces))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedEncrypted));

        verify(securityService).encrypt(trimmedPlaintext);
    }

    @Test
    void encrypt_ShouldHandleEmptyString() throws Exception {
        // Given
        String emptyString = "";
        String expectedEncrypted = "encrypted-empty-string";
        when(securityService.encrypt(emptyString)).thenReturn(expectedEncrypted);

        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(emptyString))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedEncrypted));

        verify(securityService).encrypt(emptyString);
    }

    @Test
    void encrypt_ShouldReturnInternalServerError_WhenServiceThrowsException() throws Exception {
        // Given
        String plaintext = "Hello World!";
        when(securityService.encrypt(anyString())).thenThrow(new GeneralSecurityException("Encryption failed"));

        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(plaintext))
                .andExpect(status().isInternalServerError());

        verify(securityService).encrypt(plaintext);
    }

    @Test
    void decrypt_ShouldReturnDecryptedText_WhenGivenValidCiphertext() throws Exception {
        // Given
        String ciphertext = "encrypted-base64-string";
        String expectedDecrypted = "Hello World!";
        when(securityService.decrypt(ciphertext)).thenReturn(expectedDecrypted);

        // When & Then
        mockMvc.perform(post("/decrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(ciphertext))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedDecrypted));

        verify(securityService).decrypt(ciphertext);
    }

    @Test
    void decrypt_ShouldTrimInputAndReturnDecryptedText() throws Exception {
        // Given
        String ciphertextWithSpaces = "  encrypted-base64-string  ";
        String trimmedCiphertext = "encrypted-base64-string";
        String expectedDecrypted = "Hello World!";
        when(securityService.decrypt(trimmedCiphertext)).thenReturn(expectedDecrypted);

        // When & Then
        mockMvc.perform(post("/decrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(ciphertextWithSpaces))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedDecrypted));

        verify(securityService).decrypt(trimmedCiphertext);
    }

    @Test
    void decrypt_ShouldReturnInternalServerError_WhenServiceThrowsException() throws Exception {
        // Given
        String ciphertext = "invalid-ciphertext";
        when(securityService.decrypt(anyString())).thenThrow(new GeneralSecurityException("Decryption failed"));

        // When & Then
        mockMvc.perform(post("/decrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(ciphertext))
                .andExpect(status().isInternalServerError());

        verify(securityService).decrypt(ciphertext);
    }

    @Test
    void generateKey_ShouldReturnNewKey_WhenCalled() throws Exception {
        // Given
        String expectedKey = "new-generated-key-base64";
        when(securityService.generateKey()).thenReturn(expectedKey);

        // When & Then
        mockMvc.perform(post("/key/generate"))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedKey));

        verify(securityService).generateKey();
    }

    @Test
    void generateKey_ShouldReturnInternalServerError_WhenServiceThrowsGeneralSecurityException() throws Exception {
        // Given
        when(securityService.generateKey()).thenThrow(new GeneralSecurityException("Key generation failed"));

        // When & Then
        mockMvc.perform(post("/key/generate"))
                .andExpect(status().isInternalServerError());

        verify(securityService).generateKey();
    }

    @Test
    void generateKey_ShouldReturnInternalServerError_WhenServiceThrowsIOException() throws Exception {
        // Given
        when(securityService.generateKey()).thenThrow(new IOException("IO error during key generation"));

        // When & Then
        mockMvc.perform(post("/key/generate"))
                .andExpect(status().isInternalServerError());

        verify(securityService).generateKey();
    }

    @Test
    void encrypt_ShouldReturn400_WhenNoBodyProvided() throws Exception {
        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN))
                .andExpect(status().isBadRequest());

        verify(securityService, never()).encrypt(anyString());
    }

    @Test
    void decrypt_ShouldReturn400_WhenNoBodyProvided() throws Exception {
        // When & Then
        mockMvc.perform(post("/decrypt")
                        .contentType(MediaType.TEXT_PLAIN))
                .andExpect(status().isBadRequest());

        verify(securityService, never()).decrypt(anyString());
    }

    @Test
    void encrypt_ShouldReturn415_WhenWrongContentType() throws Exception {
        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"Hello World!\"}"))
                .andExpect(status().isUnsupportedMediaType());

        verify(securityService, never()).encrypt(anyString());
    }

    @Test
    void decrypt_ShouldReturn415_WhenWrongContentType() throws Exception {
        // When & Then
        mockMvc.perform(post("/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\":\"encrypted-text\"}"))
                .andExpect(status().isUnsupportedMediaType());

        verify(securityService, never()).decrypt(anyString());
    }

    @Test
    void encrypt_ShouldHandleSpecialCharacters() throws Exception {
        // Given
        String specialChars = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?";
        String expectedEncrypted = "encrypted-special-chars";
        when(securityService.encrypt(specialChars)).thenReturn(expectedEncrypted);

        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(specialChars))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedEncrypted));

        verify(securityService).encrypt(specialChars);
    }

    @Test
    void encrypt_ShouldHandleUnicodeCharacters() throws Exception {
        // Given
        String unicodeText = "Unicode: 你好世界 🌍 émojis";
        String expectedEncrypted = "encrypted-unicode-text";
        when(securityService.encrypt(unicodeText)).thenReturn(expectedEncrypted);

        // When & Then
        mockMvc.perform(post("/encrypt")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(unicodeText))
                .andExpect(status().isOk())
                .andExpect(content().string(expectedEncrypted));

        verify(securityService).encrypt(unicodeText);
    }
}

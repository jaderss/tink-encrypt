package dev.jaderss.encrypt.service;

public class CiphertextRejectedException extends RuntimeException {

    public CiphertextRejectedException(Throwable cause) {
        super("ciphertext rejected", cause);
    }
}

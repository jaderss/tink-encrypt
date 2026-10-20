package dev.jaderss.encrypt.controller;

public record PlaintextResponse(String plaintext) {

    @Override
    public String toString() {
        return "PlaintextResponse[plaintext=***]";
    }
}

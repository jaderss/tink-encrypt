package dev.jaderss.encrypt.controller;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PlaintextRecordsTest {

    @Test
    void plaintextRequestHidesPlaintextFromToString() {
        assertThat(new PlaintextRequest(CONTEXT, "123-45-6789"))
                .hasToString("PlaintextRequest[context=EncryptionContext[tenantId=acme, field=ssn], plaintext=***]");
    }

    @Test
    void plaintextResponseHidesPlaintextFromToString() {
        assertThat(new PlaintextResponse("123-45-6789")).hasToString("PlaintextResponse[plaintext=***]");
    }
}

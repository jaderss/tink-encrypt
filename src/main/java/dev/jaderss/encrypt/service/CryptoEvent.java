package dev.jaderss.encrypt.service;

import dev.jaderss.encrypt.request.RequestContext;
import jdk.jfr.Category;
import jdk.jfr.Description;
import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

@Name(CryptoEvent.NAME)
@Label("Crypto Operation")
@Description("Latency and outcome of one encrypt or decrypt call")
@Category("Encrypt")
@StackTrace(false)
class CryptoEvent extends Event {

    static final String NAME = "dev.jaderss.encrypt.Crypto";

    @Label("Operation")
    final String operation;

    @Label("Tenant")
    final String tenantId;

    @Label("Field")
    final String field;

    @Label("Request Id")
    final String requestId;

    @Label("Success")
    boolean success;

    CryptoEvent(String operation, EncryptionContext context) {
        this.operation = operation;
        this.tenantId = context.tenantId();
        this.field = context.field();
        this.requestId = RequestContext.currentRequestId();
    }
}

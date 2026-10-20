package dev.jaderss.encrypt.request;

import java.util.Objects;

public record RequestContext(String requestId) {

    public static final ScopedValue<RequestContext> CURRENT = ScopedValue.newInstance();

    public RequestContext {
        Objects.requireNonNull(requestId, "requestId");
    }

    public static String currentRequestId() {
        return CURRENT.isBound() ? CURRENT.get().requestId() : null;
    }
}

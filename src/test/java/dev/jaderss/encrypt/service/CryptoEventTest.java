package dev.jaderss.encrypt.service;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

import com.google.crypto.tink.Aead;
import dev.jaderss.encrypt.keyset.Keysets;
import dev.jaderss.encrypt.request.RequestContext;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CryptoEventTest {

    @TempDir
    Path tempDir;

    @Test
    void recordsOneEventPerOperationWithOutcomeAndRequestId() throws Exception {
        SecurityService securityService =
                new SecurityService(Keysets.parse(Keysets.generate()).getPrimitive(Aead.class));

        List<RecordedEvent> events = record(() -> ScopedValue.where(RequestContext.CURRENT, new RequestContext("req-7"))
                .call(() -> {
                    String ciphertext = securityService.encrypt(CONTEXT, "123-45-6789");
                    securityService.decrypt(CONTEXT, ciphertext);
                    assertThatThrownBy(() -> securityService.decrypt(CONTEXT, "not-a-ciphertext"))
                            .isInstanceOf(CiphertextRejectedException.class);
                    return null;
                }));

        assertThat(events)
                .extracting(
                        event -> event.getString("operation"),
                        event -> event.getBoolean("success"),
                        event -> event.getString("tenantId"),
                        event -> event.getString("field"),
                        event -> event.getString("requestId"))
                .containsExactly(
                        tuple("encrypt", true, "acme", "ssn", "req-7"),
                        tuple("decrypt", true, "acme", "ssn", "req-7"),
                        tuple("decrypt", false, "acme", "ssn", "req-7"));
        assertThat(events).allSatisfy(event -> assertThat(event.getDuration()).isPositive());
    }

    private List<RecordedEvent> record(ScopedValue.CallableOp<Void, Exception> operations) throws Exception {
        Path file = tempDir.resolve("crypto.jfr");
        try (Recording recording = new Recording()) {
            recording.enable(CryptoEvent.NAME).withThreshold(Duration.ZERO);
            recording.start();
            operations.call();
            recording.stop();
            recording.dump(file);
        }
        return readEvents(file);
    }

    private static List<RecordedEvent> readEvents(Path file) throws IOException {
        return RecordingFile.readAllEvents(file).stream()
                .filter(event -> event.getEventType().getName().equals(CryptoEvent.NAME))
                .toList();
    }
}

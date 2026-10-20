package dev.jaderss.encrypt.keyset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class KeysetsTest {

    @Test
    void generateCreatesKeysetWithSinglePrimaryKey() throws GeneralSecurityException {
        KeysetHandle keyset = Keysets.parse(Keysets.generate());

        assertThat(keyset.size()).isOne();
        assertThat(keyset.getAt(0).isPrimary()).isTrue();
    }

    @Test
    void rotateAddsNewPrimaryAndKeepsPreviousKey() throws GeneralSecurityException {
        KeysetHandle original = Keysets.parse(Keysets.generate());
        KeysetHandle rotated = Keysets.parse(Keysets.rotate(Keysets.encode(original)));

        assertThat(rotated.size()).isEqualTo(2);
        assertThat(rotated.getPrimary().getId())
                .isNotEqualTo(original.getPrimary().getId());
        assertThat(rotated.getAt(0).getId()).isEqualTo(original.getPrimary().getId());
    }

    @Test
    void retireKeepsOnlyPrimaryKey() throws GeneralSecurityException {
        String rotated = Keysets.rotate(Keysets.rotate(Keysets.generate()));
        int primaryId = Keysets.parse(rotated).getPrimary().getId();

        KeysetHandle retired = Keysets.parse(Keysets.retire(rotated));

        assertThat(retired.size()).isOne();
        assertThat(retired.getPrimary().getId()).isEqualTo(primaryId);
    }

    @Test
    void unwrapRestoresKeysetWrappedWithSameKeyEncryptionKey() throws GeneralSecurityException {
        Aead keyEncryptionKey = Keysets.parse(Keysets.generate()).getPrimitive(Aead.class);
        String keyset = Keysets.generate();

        KeysetHandle unwrapped = Keysets.unwrap(Keysets.wrap(keyset, keyEncryptionKey), keyEncryptionKey);

        assertThat(Keysets.encode(unwrapped)).isEqualTo(keyset);
    }

    @Test
    void unwrapFailsWithAnotherKeyEncryptionKey() throws GeneralSecurityException {
        Aead keyEncryptionKey = Keysets.parse(Keysets.generate()).getPrimitive(Aead.class);
        Aead otherKey = Keysets.parse(Keysets.generate()).getPrimitive(Aead.class);
        String wrapped = Keysets.wrap(Keysets.generate(), keyEncryptionKey);

        assertThatThrownBy(() -> Keysets.unwrap(wrapped, otherKey)).isInstanceOf(GeneralSecurityException.class);
    }

    @Nested
    class CommandLine {

        private final Aead keyEncryptionKey = Keysets.parse(Keysets.generate()).getPrimitive(Aead.class);

        CommandLine() throws GeneralSecurityException {}

        @Test
        void newPrintsCleartextKeysetWithoutKms() throws GeneralSecurityException {
            String keyset = Keysets.run("new", Map.of(), keyArn -> keyEncryptionKey);

            assertThat(Keysets.parse(keyset).size()).isOne();
        }

        @Test
        void newPrintsOnlyWrappedKeysetInKmsMode() throws GeneralSecurityException {
            String output = Keysets.run("new", kmsEnv(), keyArn -> keyEncryptionKey);

            assertThatThrownBy(() -> Keysets.parse(output)).isInstanceOf(GeneralSecurityException.class);
            assertThat(Keysets.unwrap(output, keyEncryptionKey).size()).isOne();
        }

        @Test
        void rotateInKmsModeUnwrapsRotatesAndWrapsAgain() throws GeneralSecurityException {
            String wrapped = Keysets.wrap(Keysets.generate(), keyEncryptionKey);
            int originalPrimary =
                    Keysets.unwrap(wrapped, keyEncryptionKey).getPrimary().getId();
            Map<String, String> env = Map.of(
                    "ENCRYPT_KMS_KEY_ARN",
                    "arn:aws:kms:us-east-1:000000000000:key/test",
                    "ENCRYPT_KMS_ENCRYPTED_KEYSET",
                    wrapped);

            String output = Keysets.run("rotate", env, keyArn -> keyEncryptionKey);

            assertThatThrownBy(() -> Keysets.parse(output)).isInstanceOf(GeneralSecurityException.class);
            KeysetHandle rotated = Keysets.unwrap(output, keyEncryptionKey);
            assertThat(rotated.size()).isEqualTo(2);
            assertThat(rotated.getAt(0).getId()).isEqualTo(originalPrimary);
        }

        @Test
        void kmsModeUsesKeyArnFromEnvironment() throws GeneralSecurityException {
            List<String> requestedArns = new ArrayList<>();

            Keysets.run("new", kmsEnv(), keyArn -> {
                requestedArns.add(keyArn);
                return keyEncryptionKey;
            });

            assertThat(requestedArns).containsExactly("arn:aws:kms:us-east-1:000000000000:key/test");
        }

        @Test
        void rejectsUnknownCommandWithUsage() {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Keysets.run("bogus", Map.of(), keyArn -> keyEncryptionKey))
                    .withMessageContaining("usage");
        }

        private static Map<String, String> kmsEnv() {
            return Map.of("ENCRYPT_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000000000000:key/test");
        }
    }
}

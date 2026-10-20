package dev.jaderss.encrypt.keyset;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.crypto.tink.KeysetHandle;
import java.security.GeneralSecurityException;
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
}

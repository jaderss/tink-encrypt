package dev.jaderss.encrypt.kdf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.Aead;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class TenantKeyDerivationTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] PLAINTEXT = "123-45-6789".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ASSOCIATED_DATA = "acme:ssn".getBytes(StandardCharsets.UTF_8);

    private final byte[] masterSecret = randomBytes(32);
    private final byte[] salt = randomBytes(16);
    private final TenantKeyDerivation derivation = new TenantKeyDerivation(masterSecret, salt);

    @Test
    void hkdfMatchesRfc5869TestCaseOne() throws GeneralSecurityException {
        byte[] okm = TenantKeyDerivation.hkdfSha256(
                HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                HEX.parseHex("000102030405060708090a0b0c"),
                HEX.parseHex("f0f1f2f3f4f5f6f7f8f9"),
                42);

        assertThat(HEX.formatHex(okm))
                .isEqualTo("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    @Test
    void sameTenantDerivesSameKeyFromSameMasterSecret() throws GeneralSecurityException {
        byte[] ciphertext = derivation.aeadFor("acme").encrypt(PLAINTEXT, ASSOCIATED_DATA);

        Aead rederived = new TenantKeyDerivation(masterSecret, salt).aeadFor("acme");

        assertThat(rederived.decrypt(ciphertext, ASSOCIATED_DATA)).isEqualTo(PLAINTEXT);
    }

    @Test
    void tenantCannotDecryptAnotherTenantsCiphertext() throws GeneralSecurityException {
        byte[] ciphertext = derivation.aeadFor("acme").encrypt(PLAINTEXT, ASSOCIATED_DATA);

        assertThatThrownBy(() -> derivation.aeadFor("globex").decrypt(ciphertext, ASSOCIATED_DATA))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void differentSaltDerivesDifferentKey() throws GeneralSecurityException {
        byte[] ciphertext = derivation.aeadFor("acme").encrypt(PLAINTEXT, ASSOCIATED_DATA);
        Aead otherSalt = new TenantKeyDerivation(masterSecret, randomBytes(16)).aeadFor("acme");

        assertThatThrownBy(() -> otherSalt.decrypt(ciphertext, ASSOCIATED_DATA))
                .isInstanceOf(GeneralSecurityException.class);
    }

    @Test
    void changingCallerArrayAfterConstructionDoesNotChangeKeys() throws GeneralSecurityException {
        byte[] callerSecret = masterSecret.clone();
        TenantKeyDerivation copied = new TenantKeyDerivation(callerSecret, salt);
        byte[] ciphertext = copied.aeadFor("acme").encrypt(PLAINTEXT, ASSOCIATED_DATA);

        Arrays.fill(callerSecret, (byte) 0);

        assertThat(copied.aeadFor("acme").decrypt(ciphertext, ASSOCIATED_DATA)).isEqualTo(PLAINTEXT);
    }

    @Test
    void rejectsMasterSecretShorterThanKey() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new TenantKeyDerivation(randomBytes(31), salt))
                .withMessageContaining("32 bytes");
    }

    @Test
    void rejectsBlankTenantId() {
        assertThatIllegalArgumentException().isThrownBy(() -> derivation.aeadFor(" "));
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}

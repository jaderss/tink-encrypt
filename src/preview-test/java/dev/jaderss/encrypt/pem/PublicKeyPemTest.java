package dev.jaderss.encrypt.pem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.PredefinedHybridParameters;
import dev.jaderss.encrypt.keyset.Keysets;
import java.security.GeneralSecurityException;
import java.security.PEMDecoder;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class PublicKeyPemTest {

    @Test
    void encodesHpkePublicKeyAsSubjectPublicKeyInfoPem() throws GeneralSecurityException {
        String publicKeyset = Keysets.publicKeyset(Keysets.generateHybrid());

        String pem = PublicKeyPem.encode(publicKeyset);

        assertThat(pem).startsWith("-----BEGIN PUBLIC KEY-----").contains("-----END PUBLIC KEY-----");
    }

    @Test
    void decodedPemCarriesSameKeyBytesAsTinkKeyset() throws GeneralSecurityException {
        String publicKeyset = Keysets.publicKeyset(Keysets.generateHybrid());
        HpkePublicKey tinkKey = (HpkePublicKey) TinkProtoKeysetFormat.parseKeysetWithoutSecret(
                        Base64.getDecoder().decode(publicKeyset))
                .getPrimary()
                .getKey();

        PublicKey decoded = PEMDecoder.of().decode(PublicKeyPem.encode(publicKeyset), PublicKey.class);
        byte[] encoded = decoded.getEncoded();

        assertThat(decoded.getAlgorithm()).isIn("X25519", "XDH");
        assertThat(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length))
                .isEqualTo(tinkKey.getPublicKeyBytes().toByteArray());
    }

    @Test
    void rejectsHpkePublicKeyThatIsNotX25519() throws GeneralSecurityException {
        HybridConfig.register();
        String p256PublicKeyset = Keysets.encodePublic(
                KeysetHandle.generateNew(PredefinedHybridParameters.HPKE_P256_HKDF_SHA256_AES_128_GCM)
                        .getPublicKeysetHandle());

        assertThatThrownBy(() -> PublicKeyPem.encode(p256PublicKeyset))
                .isInstanceOf(GeneralSecurityException.class)
                .hasMessageContaining("X25519");
    }
}

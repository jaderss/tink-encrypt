package dev.jaderss.encrypt.pem;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import dev.jaderss.encrypt.keyset.Keysets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PEMEncoder;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;

public final class PublicKeyPem {

    private static final byte[] X25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX =
            HexFormat.of().parseHex("302a300506032b656e032100");

    private PublicKeyPem() {}

    public static String encode(String publicKeyset) throws GeneralSecurityException {
        Key key = TinkProtoKeysetFormat.parseKeysetWithoutSecret(
                        Base64.getDecoder().decode(publicKeyset))
                .getPrimary()
                .getKey();
        if (!(key instanceof HpkePublicKey hpke)
                || hpke.getParameters().getKemId() != HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256) {
            throw new GeneralSecurityException("only HPKE X25519 public keys can be exported as PEM");
        }
        return PEMEncoder.of()
                .encodeToString(x25519PublicKey(hpke.getPublicKeyBytes().toByteArray()));
    }

    static PublicKey x25519PublicKey(byte[] rawPublicKey) throws GeneralSecurityException {
        byte[] encoded = new byte[X25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX.length + rawPublicKey.length];
        System.arraycopy(
                X25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX, 0, encoded, 0, X25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX.length);
        System.arraycopy(rawPublicKey, 0, encoded, X25519_SUBJECT_PUBLIC_KEY_INFO_PREFIX.length, rawPublicKey.length);
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static void main(String[] args) throws GeneralSecurityException {
        String hybridKeyset = Objects.requireNonNull(System.getenv("ENCRYPT_HYBRID_KEYSET"), "ENCRYPT_HYBRID_KEYSET");
        System.out.println(encode(Keysets.publicKeyset(hybridKeyset)));
    }
}

package dev.jaderss.encrypt.keyset;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.integration.awskms.AwsKmsAead;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import software.amazon.awssdk.services.kms.KmsClient;

public final class Keysets {

    private static final Parameters AEAD_PARAMETERS = PredefinedAeadParameters.AES256_GCM;
    private static final String KMS_KEY_ARN = "ENCRYPT_KMS_KEY_ARN";
    private static final byte[] WRAPPED_KEYSET_LABEL = "tink-encrypt/keyset/v1".getBytes(StandardCharsets.UTF_8);

    static {
        try {
            AeadConfig.register();
            HybridConfig.register();
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private Keysets() {}

    public static String generate() throws GeneralSecurityException {
        return encode(KeysetHandle.generateNew(AEAD_PARAMETERS));
    }

    public static String generateHybrid() throws GeneralSecurityException {
        return encode(KeysetHandle.generateNew(HpkeParameters.builder()
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .setVariant(HpkeParameters.Variant.TINK)
                .build()));
    }

    public static String publicKeyset(String hybridKeyset) throws GeneralSecurityException {
        return encodePublic(parse(hybridKeyset).getPublicKeysetHandle());
    }

    public static String encodePublic(KeysetHandle publicKeyset) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeyset));
    }

    public static String rotate(String keyset) throws GeneralSecurityException {
        return encode(KeysetHandle.newBuilder(parse(keyset))
                .addEntry(KeysetHandle.generateEntryFromParameters(AEAD_PARAMETERS)
                        .withRandomId()
                        .makePrimary())
                .build());
    }

    public static String retire(String keyset) throws GeneralSecurityException {
        KeysetHandle.Builder builder = KeysetHandle.newBuilder(parse(keyset));
        for (int i = builder.size() - 1; i >= 0; i--) {
            if (!builder.getAt(i).isPrimary()) {
                builder.deleteAt(i);
            }
        }
        return encode(builder.build());
    }

    public static KeysetHandle parse(String keyset) throws GeneralSecurityException {
        return TinkProtoKeysetFormat.parseKeyset(Base64.getDecoder().decode(keyset), InsecureSecretKeyAccess.get());
    }

    public static String encode(KeysetHandle handle) throws GeneralSecurityException {
        return Base64.getEncoder()
                .encodeToString(TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()));
    }

    public static String wrap(String keyset, Aead keyEncryptionKey) throws GeneralSecurityException {
        byte[] encrypted =
                TinkProtoKeysetFormat.serializeEncryptedKeyset(parse(keyset), keyEncryptionKey, WRAPPED_KEYSET_LABEL);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static KeysetHandle unwrap(String encryptedKeyset, Aead keyEncryptionKey) throws GeneralSecurityException {
        return TinkProtoKeysetFormat.parseEncryptedKeyset(
                Base64.getDecoder().decode(encryptedKeyset), keyEncryptionKey, WRAPPED_KEYSET_LABEL);
    }

    public static void main(String[] args) throws GeneralSecurityException {
        String command = args.length == 1 ? args[0] : "";
        try (KmsClient kmsClient = System.getenv(KMS_KEY_ARN) == null ? null : KmsClient.create()) {
            System.out.println(run(command, System.getenv(), keyArn -> new AwsKmsAead(kmsClient, keyArn)));
        }
    }

    static String run(String command, Map<String, String> env, Function<String, Aead> keyEncryptionKeyFor)
            throws GeneralSecurityException {
        String keyArn = env.get(KMS_KEY_ARN);
        Aead keyEncryptionKey = keyArn == null ? null : keyEncryptionKeyFor.apply(keyArn);
        return switch (command) {
            case "new" -> protect(generate(), keyEncryptionKey);
            case "rotate" -> protect(rotate(currentKeyset(env, keyEncryptionKey)), keyEncryptionKey);
            case "retire" -> protect(retire(currentKeyset(env, keyEncryptionKey)), keyEncryptionKey);
            case "new-hybrid" -> generateHybrid();
            case "public-key" -> publicKeyset(required(env, "ENCRYPT_HYBRID_KEYSET"));
            default ->
                throw new IllegalArgumentException("usage: scripts/keyset.sh new|rotate|retire|new-hybrid|public-key");
        };
    }

    private static String protect(String keyset, Aead keyEncryptionKey) throws GeneralSecurityException {
        return keyEncryptionKey == null ? keyset : wrap(keyset, keyEncryptionKey);
    }

    private static String currentKeyset(Map<String, String> env, Aead keyEncryptionKey)
            throws GeneralSecurityException {
        return keyEncryptionKey == null
                ? required(env, "ENCRYPT_KEYSET")
                : encode(unwrap(required(env, "ENCRYPT_KMS_ENCRYPTED_KEYSET"), keyEncryptionKey));
    }

    private static String required(Map<String, String> env, String name) {
        return Objects.requireNonNull(env.get(name), name);
    }
}

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
import java.util.Objects;
import software.amazon.awssdk.services.kms.KmsClient;

public final class Keysets {

    private static final Parameters AEAD_PARAMETERS = PredefinedAeadParameters.AES256_GCM;
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
        switch (command) {
            case "new-hybrid" -> System.out.println(generateHybrid());
            case "public-key" -> System.out.println(publicKeyset(requiredEnv("ENCRYPT_HYBRID_KEYSET")));
            default -> System.out.println(runAeadCommand(command));
        }
    }

    private static String runAeadCommand(String command) throws GeneralSecurityException {
        String keyArn = System.getenv("ENCRYPT_KMS_KEY_ARN");
        try (KmsClient kmsClient = keyArn == null ? null : KmsClient.create()) {
            Aead keyEncryptionKey = keyArn == null ? null : new AwsKmsAead(kmsClient, keyArn);
            String keyset = switch (command) {
                case "new" -> generate();
                case "rotate" -> rotate(currentKeyset(keyEncryptionKey));
                case "retire" -> retire(currentKeyset(keyEncryptionKey));
                default ->
                    throw new IllegalArgumentException(
                            "usage: scripts/keyset.sh new|rotate|retire|new-hybrid|public-key");
            };
            return keyEncryptionKey == null ? keyset : wrap(keyset, keyEncryptionKey);
        }
    }

    private static String currentKeyset(Aead keyEncryptionKey) throws GeneralSecurityException {
        return keyEncryptionKey == null
                ? requiredEnv("ENCRYPT_KEYSET")
                : encode(unwrap(requiredEnv("ENCRYPT_KMS_ENCRYPTED_KEYSET"), keyEncryptionKey));
    }

    private static String requiredEnv(String name) {
        return Objects.requireNonNull(System.getenv(name), name);
    }
}

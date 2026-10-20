package dev.jaderss.encrypt.kdf;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;

public final class TenantKeyDerivation {

    private static final int KEY_SIZE_BYTES = 32;
    private static final String INFO_PREFIX = "tink-encrypt/tenant-data-key/v1\0";

    private final byte[] masterSecret;
    private final byte[] salt;

    public TenantKeyDerivation(byte[] masterSecret, byte[] salt) {
        Objects.requireNonNull(masterSecret, "masterSecret");
        Objects.requireNonNull(salt, "salt");
        if (masterSecret.length < KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("masterSecret must be at least " + KEY_SIZE_BYTES + " bytes");
        }
        this.masterSecret = masterSecret.clone();
        this.salt = salt.clone();
    }

    public Aead aeadFor(String tenantId) throws GeneralSecurityException {
        Objects.requireNonNull(tenantId, "tenantId");
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        AeadConfig.register();
        byte[] info = (INFO_PREFIX + tenantId).getBytes(StandardCharsets.UTF_8);
        AesGcmKey key = AesGcmKey.builder()
                .setParameters(aesGcm256())
                .setKeyBytes(SecretBytes.copyFrom(
                        hkdfSha256(masterSecret, salt, info, KEY_SIZE_BYTES), InsecureSecretKeyAccess.get()))
                .build();
        return KeysetHandle.newBuilder()
                .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
                .build()
                .getPrimitive(Aead.class);
    }

    static byte[] hkdfSha256(byte[] inputKeyMaterial, byte[] salt, byte[] info, int length)
            throws GeneralSecurityException {
        return KDF.getInstance("HKDF-SHA256")
                .deriveData(HKDFParameterSpec.ofExtract()
                        .addIKM(inputKeyMaterial)
                        .addSalt(salt)
                        .thenExpand(info, length));
    }

    private static AesGcmParameters aesGcm256() throws GeneralSecurityException {
        return AesGcmParameters.builder()
                .setKeySizeBytes(KEY_SIZE_BYTES)
                .setIvSizeBytes(12)
                .setTagSizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build();
    }
}

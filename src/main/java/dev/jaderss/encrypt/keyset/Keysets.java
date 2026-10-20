package dev.jaderss.encrypt.keyset;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;

public final class Keysets {

    private static final Parameters AEAD_PARAMETERS = PredefinedAeadParameters.AES256_GCM;

    static {
        try {
            AeadConfig.register();
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private Keysets() {}

    public static String generate() throws GeneralSecurityException {
        return encode(KeysetHandle.generateNew(AEAD_PARAMETERS));
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

    public static void main(String[] args) throws GeneralSecurityException {
        String command = args.length == 1 ? args[0] : "";
        System.out.println(
                switch (command) {
                    case "new" -> generate();
                    case "rotate" -> rotate(currentKeyset());
                    case "retire" -> retire(currentKeyset());
                    default -> throw new IllegalArgumentException("usage: scripts/keyset.sh new|rotate|retire");
                });
    }

    private static String currentKeyset() {
        return Objects.requireNonNull(System.getenv("ENCRYPT_KEYSET"), "ENCRYPT_KEYSET");
    }
}

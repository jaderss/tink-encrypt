package dev.jaderss.encrypt;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;

@TestConfiguration(proxyBeanMethods = false)
public class TestKeysetConfig {

    public static String newKeyset() throws GeneralSecurityException {
        AeadConfig.register();
        return encode(KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM));
    }

    public static String encode(KeysetHandle handle) throws GeneralSecurityException {
        byte[] keyset = TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
        return Base64.getEncoder().encodeToString(keyset);
    }

    @Bean
    DynamicPropertyRegistrar encryptKeyset() throws GeneralSecurityException {
        String keyset = newKeyset();
        return registry -> registry.add("encrypt.keyset", () -> keyset);
    }
}

package dev.jaderss.encrypt.config;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(EncryptProperties.class)
public class SecurityConfig {

    @Bean
    public Aead aead(EncryptProperties properties) throws GeneralSecurityException {
        AeadConfig.register();
        byte[] keyset = Base64.getDecoder().decode(properties.keyset());
        return TinkProtoKeysetFormat.parseKeyset(keyset, InsecureSecretKeyAccess.get())
                .getPrimitive(Aead.class);
    }
}

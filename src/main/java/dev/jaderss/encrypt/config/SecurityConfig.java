package dev.jaderss.encrypt.config;

import com.google.crypto.tink.Aead;
import dev.jaderss.encrypt.keyset.Keysets;
import java.security.GeneralSecurityException;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(EncryptProperties.class)
public class SecurityConfig {

    @Bean
    public Aead aead(EncryptProperties properties) throws GeneralSecurityException {
        return Keysets.parse(properties.keyset()).getPrimitive(Aead.class);
    }
}

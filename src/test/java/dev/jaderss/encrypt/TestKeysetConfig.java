package dev.jaderss.encrypt;

import dev.jaderss.encrypt.keyset.Keysets;
import java.security.GeneralSecurityException;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;

@TestConfiguration(proxyBeanMethods = false)
public class TestKeysetConfig {

    @Bean
    DynamicPropertyRegistrar encryptKeyset() throws GeneralSecurityException {
        String keyset = Keysets.generate();
        return registry -> registry.add("encrypt.keyset", () -> keyset);
    }
}

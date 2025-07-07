package dev.jaderss.encrypt.config;

import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;

@Configuration
@Slf4j
public class SecurityConfig {

    @Bean
    public KeysetHandle keysetHandle(@Value("${encrypt.key}") String key) throws GeneralSecurityException, IOException {
        AeadConfig.register();
        byte[] plainKey = Base64.getDecoder().decode(key);
        return CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(plainKey));
    }
}
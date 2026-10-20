package dev.jaderss.encrypt.config;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.integration.awskms.AwsKmsAead;
import dev.jaderss.encrypt.keyset.Keysets;
import dev.jaderss.encrypt.service.HybridImportService;
import dev.jaderss.encrypt.service.SecurityService;
import java.security.GeneralSecurityException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.kms.KmsClient;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(EncryptProperties.class)
public class SecurityConfig {

    @Bean
    public Aead aead(EncryptProperties properties, ObjectProvider<KmsClient> kmsClient)
            throws GeneralSecurityException {
        EncryptProperties.Kms kms = properties.kms();
        KeysetHandle keyset = kms == null
                ? Keysets.parse(properties.keyset())
                : Keysets.unwrap(kms.encryptedKeyset(), new AwsKmsAead(kmsClient.getObject(), kms.keyArn()));
        return keyset.getPrimitive(Aead.class);
    }

    @Bean
    @ConditionalOnProperty(prefix = "encrypt", name = "hybrid-keyset")
    public HybridImportService hybridImportService(EncryptProperties properties, SecurityService securityService)
            throws GeneralSecurityException {
        return new HybridImportService(Keysets.parse(properties.hybridKeyset()), securityService);
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(prefix = "encrypt.kms", name = "key-arn")
    public KmsClient kmsClient() {
        return KmsClient.create();
    }
}

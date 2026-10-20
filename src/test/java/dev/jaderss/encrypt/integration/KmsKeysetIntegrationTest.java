package dev.jaderss.encrypt.integration;

import static dev.jaderss.encrypt.Samples.CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.integration.awskms.AwsKmsAead;
import dev.jaderss.encrypt.keyset.Keysets;
import dev.jaderss.encrypt.service.SecurityService;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

@Testcontainers
@SpringBootTest
@ActiveProfiles("aws")
class KmsKeysetIntegrationTest {

    @Container
    static final LocalStackContainer LOCALSTACK =
            new LocalStackContainer(DockerImageName.parse("localstack/localstack:4.14.0")).withServices("kms");

    private static String keyArn;
    private static String keyset;
    private static String wrappedKeyset;

    @TestBean
    private KmsClient kmsClient;

    @Autowired
    private SecurityService securityService;

    @BeforeAll
    static void wrapKeysetWithKmsKey() throws GeneralSecurityException {
        try (KmsClient kms = kmsClient()) {
            keyArn = createKey(kms);
            keyset = Keysets.generate();
            wrappedKeyset = Keysets.wrap(keyset, new AwsKmsAead(kms, keyArn));
        }
    }

    @DynamicPropertySource
    static void kmsProperties(DynamicPropertyRegistry registry) {
        registry.add("encrypt.kms.key-arn", () -> keyArn);
        registry.add("encrypt.kms.encrypted-keyset", () -> wrappedKeyset);
    }

    static KmsClient kmsClient() {
        return KmsClient.builder()
                .endpointOverride(LOCALSTACK.getEndpoint())
                .region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(LOCALSTACK.getAccessKey(), LOCALSTACK.getSecretKey())))
                .build();
    }

    @Test
    void serviceDecryptsWhatItEncryptsWithKeysetUnwrappedByKms() throws GeneralSecurityException {
        assertThat(securityService.decrypt(CONTEXT, securityService.encrypt(CONTEXT, "123-45-6789")))
                .isEqualTo("123-45-6789");
    }

    @Test
    void serviceUsesExactlyTheKeysetThatWasWrapped() throws GeneralSecurityException {
        String ciphertext = securityService.encrypt(CONTEXT, "123-45-6789");
        Aead original = Keysets.parse(keyset).getPrimitive(Aead.class);

        assertThat(new SecurityService(original).decrypt(CONTEXT, ciphertext)).isEqualTo("123-45-6789");
    }

    @Test
    void wrappedKeysetCannotBeUnwrappedWithAnotherKmsKey() {
        try (KmsClient kms = kmsClient()) {
            Aead otherKey = new AwsKmsAead(kms, createKey(kms));

            assertThatThrownBy(() -> Keysets.unwrap(wrappedKeyset, otherKey))
                    .isInstanceOf(GeneralSecurityException.class);
        }
    }

    @Test
    void wrappedKeysetDoesNotContainCleartextKeyset() {
        assertThat(wrappedKeyset).doesNotContain(keyset);
    }

    private static String createKey(KmsClient kms) {
        return kms.createKey(request -> request.description("tink-encrypt test key"))
                .keyMetadata()
                .arn();
    }
}

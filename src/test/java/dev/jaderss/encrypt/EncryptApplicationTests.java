package dev.jaderss.encrypt;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(TestKeysetConfig.class)
class EncryptApplicationTests {

    @Test
    void contextLoads() {}
}

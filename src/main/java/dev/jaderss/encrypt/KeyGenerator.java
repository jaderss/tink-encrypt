package dev.jaderss.encrypt;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.io.IOException;
import java.util.Base64; // Import Base64

public class KeyGenerator {

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        AeadConfig.register();
        KeysetHandle keysetHandle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
        String base64KeyString = Base64.getEncoder().encodeToString(outputStream.toByteArray());
        System.out.println(base64KeyString);
    }
}
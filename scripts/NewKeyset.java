import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.util.Base64;

public class NewKeyset {

    public static void main(String[] args) throws Exception {
        AeadConfig.register();
        KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
        byte[] keyset = TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
        System.out.println(Base64.getEncoder().encodeToString(keyset));
    }
}

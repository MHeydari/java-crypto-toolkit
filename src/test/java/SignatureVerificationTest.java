import com.neverhood.utils.CryptographyHelper;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.assertTrue;

public class SignatureVerificationTest {
    final static String data = "plain text for ...";
    final static String privateKeyAsString = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMOMSY4O0ZZ1ibfR3rKvNkMWOxFc41TQfK3PSzwZhlsFy1BDqMBlOyo9RZW92wcWNw5fhBApVBgGDemHnrySNCRUCI7mZ8wsLcPjaBYgTvG5YO4zVUCLWTMjy840nrKBCVuyqOuWS2+b5rIsPGCoTirCim66HrUS9Z5pX3VIhMOjAgMBAAECgYEAsawTYOmB8O0WllgvubaM3OOkA6CcRQGxZtMEDrU6aBWZp3HyL+1KlpRZVzbLfWLn3z1V5sFGURWfKmI5DijhCc/7rb7zP+WNDSUUY3MdEZVD1g/ZLDFMUH0ue+lv2FF5kKRjFBQsXldw0p1MPPSxxk8xvv3+9cign7ZiXot8vaECQQD5bwW4CleW77FZvVCLrKNJezA6CyuCGAex0azdH8bhOI1qp8XetfSgT9uOumwAyRgznV+khx/BYQQ5s17GwLTpAkEAyLIerb75iVjI3bxPbHFg568lKhsTF0SMvy+8jT7SB5/jlpqGA4XjqRLyhDu5EEDzomJJ487AY8pFokVx5CkMqwJBAN5nSr8doZm4YPb2IVJY/UMwrwCiIwodaQb5QNvtUIRSy2006O46aUNj0Q3DVTeiFo03HidyQDNJ0N2t/KzU+LkCQGr1OpJgN/7xuUMq660gk4OF/Sl+emMpHlV57GPeOfLkTFdkDM3t2hGuTl8YsR0vcGh3N2fYNQI5t3iux+7PzbcCQQDbBSV8pMWeoTvGW3yCXNASEXtE7FJtFayr/3rcXgM2yNCo/rZ3yZHbOMF6ze7yevvLcPzPMxzUpPWtPPg7lpGI";
    final static String publicKeyAsString = "AMOMSY4O0ZZ1ibfR3rKvNkMWOxFc41TQfK3PSzwZhlsFy1BDqMBlOyo9RZW92wcWNw5fhBApVBgGDemHnrySNCRUCI7mZ8wsLcPjaBYgTvG5YO4zVUCLWTMjy840nrKBCVuyqOuWS2+b5rIsPGCoTirCim66HrUS9Z5pX3VIhMOj";
    static PrivateKey privateKey;
    static PublicKey publicKey;

    @BeforeClass
    public static void init() throws Exception {
        privateKey = CryptographyHelper.retrievePrivateKeyFromEncoded(CryptographyHelper.decodeFromBase64(privateKeyAsString
                .getBytes()));
        publicKey = CryptographyHelper.retrievePublicKeyFromModulus(CryptographyHelper.decodeFromBase64(publicKeyAsString
                .getBytes()));
    }

    @Test
    public void verifySignature() throws Exception {
        byte[] signature = CryptographyHelper.sign(privateKey, data.getBytes(StandardCharsets.UTF_8));
        System.out.println("signature-payload: " + new String(signature));
        System.out.println("signature-payload-length: " + signature.length);

        assertTrue(CryptographyHelper.verifySignature(publicKey,
                data.getBytes(StandardCharsets.UTF_8),
                signature));
    }
}

package emma.galzio.tutorialjwtspringsecurity.security;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Configuration
public class BasicConfig {

    @Bean
    public Algorithm getJWTSignAlgorithm(@Value("${jwt.secret}") String secret) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedSecretBytes = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
        return Algorithm.HMAC256(hashedSecretBytes);
    }
}

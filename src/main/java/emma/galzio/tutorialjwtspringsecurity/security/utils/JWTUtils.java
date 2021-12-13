package emma.galzio.tutorialjwtspringsecurity.security.utils;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JWTUtils {

    private int jwtMinutesLength;
    private int refreshTokenMinutesLenght;
    private final Algorithm algorithm;


    @Value("${jwt.length.min}")
    public void setJwtMinutesLength(int jwtMinutesLength) {
        this.jwtMinutesLength = jwtMinutesLength;
    }
    @Value("${jwt.refresh.length.min}")
    public void setRefreshTokenMinutesLenght(int refreshTokenMinutesLenght) {
        this.refreshTokenMinutesLenght = refreshTokenMinutesLenght;
    }

    public String generateAccessToken(User user, String issuer){

        LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(jwtMinutesLength);
        return JWT.create().withSubject(user.getUsername())
                .withExpiresAt(Date.from(expirationTime.atZone(ZoneId.systemDefault()).toInstant()))
                .withIssuer(issuer) //indica quien emitiò la solicitud, en este caso se utiliza la URI pero puede ser cualquier cosa
                //Un claim es como un header pero del JWT, existen varios estandares como el ExpiresAt pero también se pueden
                //incluir los claims que sean necesarios con el nombre que se desee, en este caso, por ejemplo
                //se utiliza el claim roles en donde se listan los roles del usuario
                //un claim podria ser isActiveUser que indique si el usuario está activo o no, la clase User
                //de spring security tiene un campo boolean para indicar si está activo
                .withClaim("roles",user.getAuthorities()
                                        .stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                //withClaim agrega los roles o permisos que va a tener el usuario para no tener que buscarlos de nuevo en la base de datos ni guardar el estado en la aplicacion
                .sign(algorithm);
    }

    public String generateRefreshToken(User user, String issuer){
        LocalDateTime refreshTokenExpirationTime = LocalDateTime.now().plusMinutes(refreshTokenMinutesLenght);
        return JWT.create().withSubject(user.getUsername())
                .withExpiresAt(Date.from(refreshTokenExpirationTime.atZone(ZoneId.systemDefault()).toInstant()))
                .withIssuer(issuer)
                //.withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

    }
    public String generateRefreshToken(String username, String issuer, List<String> roles){
        User user = new User(username,null,
                roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        return this.generateRefreshToken(user,issuer);
    }

    public String generateAccessToken(String username, List<String> roles, String issuer){
        User user = new User(username,null, roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        return this.generateAccessToken(user,issuer);
    }

    public UsernamePasswordAuthenticationToken verfyToken(String authorizationHeader){

        DecodedJWT decodedJWT = this.getDecodedJWT(authorizationHeader);
        String username = this.getTokenUsername(decodedJWT);
        List<String> roles = this.getClaim("roles",decodedJWT);//Se le pasa el nombre
        //que se le dio al claim de los roles en successfulAuthentication en el AuthenticationFilter

        List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        //En credentials va cualquier cosa importante para la autenticación, generalmente la contraseña
        return new UsernamePasswordAuthenticationToken(username,null, authorities);
    }

    private DecodedJWT getDecodedJWT(String authorizationHeader){
        String token = authorizationHeader.substring("Bearer ".length());
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        return jwtVerifier.verify(token);
    }
    public String getTokenUsername(String authorizationHeader){
        return getDecodedJWT(authorizationHeader).getSubject();
    }
    private String getTokenUsername(DecodedJWT decodedJWT){
        return decodedJWT.getSubject();
    }
    public List<String> getClaim(String claim, String authorizationHeader){
        DecodedJWT decodedJWT = this.getDecodedJWT(authorizationHeader);
        return decodedJWT.getClaim(claim).asList(String.class);
    }
    private List<String> getClaim(String claim, DecodedJWT decodedJWT){
        return decodedJWT.getClaim(claim).asList(String.class);
    }

}

package emma.galzio.tutorialjwtspringsecurity.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import emma.galzio.tutorialjwtspringsecurity.domain.Role;
import emma.galzio.tutorialjwtspringsecurity.domain.User;
import emma.galzio.tutorialjwtspringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api/token")
@RequiredArgsConstructor
public class RefreshTokenResourse {

    private final UserService userService;

    //Todo este código es horrible, pero cuando lo haga en la otra aplicación voy a necesitar
    //darle un buen diseño a todo, sobre todo a la parte de la creacón y validación de los tokens
    //mediante clases utilitarias
    @GetMapping("/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authorizationHeader = request.getHeader(AUTHORIZATION);
        try {
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                response.setHeader("Error", "Authorization header not found");
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
            String refreshToken = authorizationHeader.substring("Bearer ".length());
            Algorithm algorithm = Algorithm.HMAC256("secretStringToEncrypt".getBytes());
            JWTVerifier jwtVerifier = JWT.require(algorithm).build();
            //Acá se valida que el refresh token no esté vencido, por eso es necesario crear otro token nuevo
            //Una vez que expiren los dos token (despues de media hora por ejemplo) el usuario deberá loguearse
            //de nuevo, pero hay casos en los que podría ser util que la sesión o el refresh token no expiren
            //Tambien se puede crear desde el principio un refresh token que dure lo suficiente como para que el usuario
            //se loguee una vez y despues por 6 meses sigue generando nuevos access tokens a partir del mismo refresh token
            DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken);
            String username = decodedJWT.getSubject();
            User user = userService.getUser(username);
            LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(15);
            String accessToken = JWT.create().withSubject(user.getUserName())
                    .withExpiresAt(Date.from(expirationTime.atZone(ZoneId.systemDefault()).toInstant()))
                    .withIssuer(request.getRequestURL().toString()) //indica quien emitiò la solicitud, en este caso se utiliza la URI pero puede ser cualquier cosa
                    .withClaim("roles",user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                    //withClaim agrega los roles o permisos que va a tener el usuario para no tener que buscarlos de nuevo en la base de datos ni guardar el estado en la aplicacion
                    .sign(algorithm);

            LocalDateTime refreshTokenExpirationTime = LocalDateTime.now().plusMinutes(30);
            String newRefreshToken = JWT.create().withSubject(user.getUserName())
                    .withExpiresAt(Date.from(refreshTokenExpirationTime.atZone(ZoneId.systemDefault()).toInstant()))
                    .withIssuer(request.getRequestURL().toString())
                    //.withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .sign(algorithm);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);
            tokens.put("refresh_token",newRefreshToken);
            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(),tokens);
        } catch(Exception e){
            Map<String, String> tokens = new HashMap<>();
            tokens.put("Error", "Ocurrió un error al verificar el refresh token");
            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(),tokens);

        }


    }
}

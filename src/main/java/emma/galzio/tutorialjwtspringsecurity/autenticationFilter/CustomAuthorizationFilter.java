package emma.galzio.tutorialjwtspringsecurity.autenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")){
            //Si la request va al endpoint de login entonces no tiene un token, por lo que no es necesario hacer nada aca
            filterChain.doFilter(request,response);
            return;
        }
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }            //Lo de Bearer es como una comprobación por lo que tengo entendido, nada más
        //if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
        try {
            String token = authorizationHeader.substring("Bearer ".length());
            Algorithm algorithm = Algorithm.HMAC256("secretStringToEncrypt".getBytes()); //Se tiene que usar alguna clase o un bean
                    //que nos aporte el algoritmo de cifrado, porque de esta forma queda redundante y poco mantenible
            //También es necesario buscar una forma de obtener un secret seguro con alguna forma de hash
            JWTVerifier jwtVerifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            String username = decodedJWT.getSubject();
            List<String> roles = decodedJWT.getClaim("roles").asList(String.class);//Se le pasa el nombre
                    //que se le dio al claim de los roles en successfulAuthentication en el AuthenticationFilter
            List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new)
                                                                                .collect(Collectors.toList());
            UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(username,null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request,response);
        }catch (Exception e){
            log.error("Ocurrió un error al autenticar y autorizar al usuario: {}", e.getMessage());
            if(e instanceof TokenExpiredException){
                response.setHeader("EXPIRED_TOKEN", "El token ya expiró");
            }
            response.setHeader("Error", "Ocurrió un error al autenticar al usuario "+e.getMessage());
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            //También se puede enviar los errores en el cuerpo de la respuesta usando el ObjectMapper
            //Como en el CustomAuthenticationFilter
            //Al usar un Map de errores en el cuerpo de la respuesta puedo dar más información de los errores
            //Pero en sí habría solo tres posibles errores, puede ser que no tenga los permisos suficientes
            //Puede ser que haya sido alterado el token y el usuario esté mañ
            //Puede ser que se haya vencido la sesión


        }
    }
    //}
}

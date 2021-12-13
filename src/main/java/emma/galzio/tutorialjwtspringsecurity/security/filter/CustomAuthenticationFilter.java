package emma.galzio.tutorialjwtspringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import emma.galzio.tutorialjwtspringsecurity.security.utils.JWTUtils;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter{


    private final AuthenticationManager authenticationManager;
    //private ApplicationContext applicationContext;
    private final JWTUtils jwtUtils;


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String userName = request.getParameter("username");
        String password = request.getParameter("password");

        //De esta forma, el usuario envía las credenciales mediante parámetros de la request, tambien se puede enviar
        //como un json en el cuerpo de la request, para eso es necesario usar un mapper
        log.info("Usuaro: {}",userName);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                            new UsernamePasswordAuthenticationToken(userName,password);
        //Crea un token con los datos del usuario
        log.info("Token name: {}",usernamePasswordAuthenticationToken.getName());
        log.info("Token credentials: {}",usernamePasswordAuthenticationToken.getCredentials());
        if(usernamePasswordAuthenticationToken.getAuthorities() != null){
            log.info("Token Roles:"); //Debería estar vacía la coleccion
            usernamePasswordAuthenticationToken.getAuthorities()
                    .forEach((authority)->log.info("Authority:{}",authority.getAuthority()));
        }
        //Intenta autenticar el usuario mediante el token, para eso calculo que llama al UserDetailService
        //loadByUsername y trata de comparar las contraseñas encriptando la contraseña pasada con BCrypt
        //Authenticate puede lanzar una AuthenticationException, que tiene un monton de subclases
        //para errores específicos
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @SneakyThrows
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authentication) throws IOException, ServletException {
        //En este método se genera el token que se envía al usuario una vez que se encuentra autenticado con
        //usuario y contraseña, se pasa a traves del objeto response
        User user = (User) authentication.getPrincipal(); //El usuario logueado en la aplicacion, clase de Spring security

        String accessToken = jwtUtils.generateAccessToken(user,request.getRequestURL().toString());

        String refreshToken = jwtUtils.generateRefreshToken(user,request.getRequestURL().toString());
        //En este caso el refresh token no lleva los permisos, es para generar un nuevo token a partir del refresh token
        //Cargando directamente los datos del usuario desde la base de datos
        //response.setHeader("access_token", accessToken); //Así se devuelven los tokens con los headers
        //response.setHeader("refresh_token", refreshToken); //Tambien se puede hacer en el cuerpo de la respuesta
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token",refreshToken);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(),tokens); //Convierte el map a JSON y lo mete en el cuerpo
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
        //Permite tomar acciones en caso de que falle el proceso de autenticacion
        //como bloquear un usuario para detener intentos de ataque por fuerza bruta (numero máximo de intentos pej)
    }
}

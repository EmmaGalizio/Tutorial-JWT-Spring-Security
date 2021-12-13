package emma.galzio.tutorialjwtspringsecurity.security.filter;

import com.auth0.jwt.exceptions.TokenExpiredException;
import emma.galzio.tutorialjwtspringsecurity.security.utils.JWTUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final JWTUtils jwtUtils;


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
        try {

            UsernamePasswordAuthenticationToken authenticationToken = jwtUtils.verfyToken(authorizationHeader);
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
}

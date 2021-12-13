package emma.galzio.tutorialjwtspringsecurity.security;

import emma.galzio.tutorialjwtspringsecurity.security.filter.CustomAuthenticationFilter;
import emma.galzio.tutorialjwtspringsecurity.security.filter.CustomAuthorizationFilter;
import emma.galzio.tutorialjwtspringsecurity.security.utils.JWTUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //Bean provisto por spring security, inyectado por constructor gracias a la annotation
    //Pero utilizamos uno personalizado
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder; //No es un bean, hay que declarar e inicializar
    private final JWTUtils jwtUtils;
    //// el bean en una clase de configuracion con @Bean

    @Override
    //Configura la primera interaccion con el sistema, cuando se provee el usuario y contraseña
    //De manera que se pueda autenticar y autorizar al usuario cargando datos desde la DDBB
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //Cuando el usuario pone sus credenciales para loguearse las envía en texto plano (via https), pero
        //cuando Spring toma la solicitud de logeo hashea la contraseña con BCryptPaswordEncoder
        //Por lo que es necesario en el servicio que gestiona la creacion y modificación del usuario agregar el encoder para
        //almacenar la contraseña hasheada
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }


    //Provee autenticacion y autorizacion mediante otros métodos, como puede ser JWT cuando ya se
    //ha logueado el usuario anteriormente y no proporciona usuario y contraseña, sino que proporciona
    //sus credenciales mediante un token
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); //Desactiva cross site recuest forgery (falsificación de petición en sitios cruzados)
        //Por defecto el login en la api es sobre la URL /login, pero si queremos lo podemos cambiar mediante el
        //CustomAuthenticationFilter
        CustomAuthenticationFilter customAuthenticationFilter
                            = new CustomAuthenticationFilter(authenticationManagerBean(), jwtUtils);
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //JWT, no almacena estado de sesion
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();
        //Ahora así el path de logueo es /api/login
        http.authorizeRequests().antMatchers("/actuator/health").permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.POST, "/api/users/**","/api/roles/**").hasAuthority("ADMIN")
                        .antMatchers(HttpMethod.GET, "/api/users/**").hasAuthority("USER");
        //http.authorizeRequests().anyRequest().authenticated(); //Cualquier peticion debe ser por alguien autenticado
        http.addFilter(customAuthenticationFilter);
        //Se utiliza addFilterBefore porque lo que se quiere es que lo primero que se haga al tratar una request
        //sea verificar si tiene un Authorization header con un token válido
        http.addFilterBefore(new CustomAuthorizationFilter(jwtUtils), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}

/***
 * WebSecurityConfigurerAdapter:
 * La autenticacion u autorizacion por tokens lleva varios pasos de configuración y son varios los objetos que intervienen
 * Primero, en la clase de configuracion web de spring security (que extiende de WebSecurityConfigurerAdapter
 * se extienden dos de los metodos configure
 * El primero, que recibe un AuthenticationManagerBuilder lo que hace es indicarle a Spring security de donde
 * va a sacar el usuario y la forma en la que se hashea la constraseña, se configura el AuthenticationManager
 * con estos datos.
 * El otro metodo que recibe un HttpSecurity es el que se encarga de controlar que recursos necesitan
 * que el usuario se identifique, y quienes tendran permiso de acceder a ellos.
 * La llamada a http.addFilter(customAuthenticationFilter) lo que hace es agregar un filtro a la request que vaya dirigida
 * a alguna de las URL indicadas en el método configure, y es este filtro el que se encarga de realizar la
 * autenticacion en tiempo de ejecución.
 * Los métodos config supongo que se llaman una sola vez cuando se inicia la aplicación, indicando de donde
 * se obtienen los usuarios, y cuales son las URL que es necesario validar
 *Filtros:
 * Los filtros se agregan manualmente con addFilter, o addFilterBefore, por eso se pueden crear como
 * POJOs e inyectarles las dependencias necesarias mediante los constructores, estaría bueno cambiar el JWTUtils por
 * una interfaz
 *
 * AuthenticationFilter: Se encarga de las tareas relacionadas con la autenticacion
 * en este caso, sobreescribi los métodos attemptAuthentication, successfulAuthentication y unsuccessfulAuthentication
 * que indican lo que se debe hacer cuando se intenta autenticar, se puede autenticar y cuando falla la autenticacion
 * attemptAuthentication recibe la request con el username y password, lo envuelve en un objeto de tipo
 * UsernamePasswordAuthentication (o algo así) y se lo pasa al AuthenticationManager junto con el encoder
 * para la contraseña para hacer la validacion (que se hace gracias al método config que indica de donde sacar el usuario,
 * contraseña y roles.
 * successfulAuthentication en este caso crea los token JWT y los devuelve en la response
 * unsuccesfulAuthentication podría enviar un mensaje en la response o un redirect, o algo así.
 * El AuthenticationFilter es el que se encarga de la autenticación por nombre de usuario y contraseña
 * utilizando el UserDetailService que se le brindó al AuthenticationManager en la clase de configuracion de Spring Security
 *
 * UserDetailService: Se implementa el método loadUserByUsername indicándole a Spring cómo debe recuperar los datos
 * del usuario y lo mapea a un objeto de usuario de Spring
 *
 * AuthorizationFilter: Extiende OncePerRecuestFilter y sobrescribe el método doFilter.
 * Es el primer filtro que se implementa porque primero debe validar si la request tiene el Authorization header
 * Si lo tiene, significa que el usuario ya se autenticó y lo que hace falta es saber si sus credenciales o permisos
 * son correctos
 * Se registra en el AutenticationManager con addFilterBefore porque es el primer filtro que se ejecuta al recibir
 * una request. La función de este filtro en este caso es verificar que la request contenga el header Authorization,
 * si lo tiene verifica que el token sea válido, y si lo es entonces ya carga los datos del usuario y los roles
 * a partir del token y genera la autorización correspondiente (autoriza o no autoriza el acceso al servicio
 * dependiendo del rol del usuario, o GranthedAuthority)
 *
 * Refresh token: Cuando el cliente se logea el servidor le envía el access token y el refresh token, el cliente
 * debe almacenar ambos. Después el cliente cuando el cliente envía otra request envía el access token al servidor.
 * Si el servidor retorna un error indicando que el access token ya expiró entonces el cliente envía otra solicitud
 * con el refresh token para otener un nuevo access token. Por eso es necesario establecer una forma de recibir
 * el refresh token, verificarlo, crear un nuevo access token a partir de él y debolverlo al cliente.
 *
 * Cuando hay un error al validar el token (roles, usuario, token expirado o lo que sea) puedo capturar
 * el tipo de error y crear una DomainExcepcion (en el otro proyecto, acá no está) y agregar las causas
 * entonces ahí directamente el handler de la excepción se encarga de la response
 *
 * Utility class para crear los tokens y verificarlos:
 * https://www.javainuse.com/webseries/spring-security-jwt/chap7
 *
 * Por lo que veo la mejor forma de generar un nuevo token a partir del refresh token es a partir
 * de un endpoint
 *
 */

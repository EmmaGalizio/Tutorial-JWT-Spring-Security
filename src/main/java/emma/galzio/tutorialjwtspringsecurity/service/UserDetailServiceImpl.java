package emma.galzio.tutorialjwtspringsecurity.service;

import emma.galzio.tutorialjwtspringsecurity.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailServiceImpl implements UserDetailsService {

    private final IUserService userService;

    /**
     *De esta forma le indicamos a Spring que debe buscar el usuario de la base de datos
     * y si lo encuentra debe retornar un objeto User (de spring) que contenga los datos del usuario
     * //estos datos los va a usar para comprobar el rol (GrantedAuthority), nombre y contraseña
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.getUser(username);
        if(user == null || user.getUserName() == null){
            log.error("The username is incorrect!");
            throw new UsernameNotFoundException("The user name is incorrect!");
        }
        log.info("We have found the user with username {}",user.getUserName());
        List<SimpleGrantedAuthority> grantedAuthorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
        //EL user de spring tiene un campo boolean enable, que sirve para validar que el
        //usuario esté activo, también tiene campos para validar que las credenciales estén activas
        return new org.springframework.security.core.userdetails.User(user.getUserName(),user.getPassword(), grantedAuthorities);
    }
}

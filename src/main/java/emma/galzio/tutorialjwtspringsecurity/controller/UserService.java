package emma.galzio.tutorialjwtspringsecurity.controller;

import emma.galzio.tutorialjwtspringsecurity.domain.Role;
import emma.galzio.tutorialjwtspringsecurity.domain.User;
import emma.galzio.tutorialjwtspringsecurity.repository.RoleRepository;
import emma.galzio.tutorialjwtspringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor //Agrega un constructor con los atributos marcados como final o @NonNull
//De esta forma se realiza la inyeccion de dependencias de spring mediante el constructor, y no mediante los campos
//Si tambien pongo @NoArgsConstructor o agrego un constructor sin parametros entonces deja la posibilidad de que
//los atributos finales no se inicialicen al crear la instancia, por lo que sería un error en tiempo de compilacion
@Slf4j //Agrega el logger de slf4j
@Transactional
public class UserService implements IUserService {

    //@Autowired
    private final UserRepository userRepository;
    //@Autowired
    private final RoleRepository roleRepository;
    private final PasswordEncoder bCryptPasswordEncoder;

    @Override
    public User saveUser(User user) {
        log.info("Saving new user with name {}",user.getName());
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role");
        return roleRepository.save(role);
    }

    @Override
    public User addRoleToUser(String userName, String roleName) {
        log.info("Adding role {} to user {}",roleName,userName);
        User user = userRepository.findByUserName(userName);
        Role role = roleRepository.findByName(roleName);

        user.addRole(role);
        //En teoria, como el método es transaccional una vez que se ejecute el método va a guardar el estado
        //en la base de datos, por lo que no hay que llamar a save
        return user;
    }

    @Override
    public User getUser(String userName) {

        log.info("Getting user {}",userName);
        return userRepository.findByUserName(userName);
    }

    @Override
    public List<User> getUsers() {
        log.info("Getting all users");
        return userRepository.findAll();
    }
}

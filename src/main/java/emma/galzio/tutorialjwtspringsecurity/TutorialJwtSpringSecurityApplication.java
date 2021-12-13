package emma.galzio.tutorialjwtspringsecurity;

import emma.galzio.tutorialjwtspringsecurity.domain.Role;
import emma.galzio.tutorialjwtspringsecurity.domain.User;
import emma.galzio.tutorialjwtspringsecurity.controller.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class TutorialJwtSpringSecurityApplication{

    public static void main(String[] args) {
        SpringApplication.run(TutorialJwtSpringSecurityApplication.class, args);
    }

    @Bean
    CommandLineRunner run(UserService userService){
        return (args)->{
          userService.saveRole(new Role(null, "ADMIN"));
          userService.saveRole(new Role(null, "USER"));
          userService.saveRole(new Role(null, "MANAGER"));

          userService.saveUser(new User(null, "Emma Galzio", "emmaG","123456",null));
          userService.saveUser(new User(null, "Mati Galizio", "matiG","123456",null));

          userService.addRoleToUser("emmaG", "ADMIN");
          userService.addRoleToUser("emmaG","MANAGER");
          userService.addRoleToUser("matiG","USER");

        };
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}

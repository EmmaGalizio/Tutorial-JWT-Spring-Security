package emma.galzio.tutorialjwtspringsecurity.api;

import emma.galzio.tutorialjwtspringsecurity.domain.Role;
import emma.galzio.tutorialjwtspringsecurity.domain.User;
import emma.galzio.tutorialjwtspringsecurity.service.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.hateoas.PagedModel;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor //agrega un constructor que incluye todos los atributos finales y NonNull y los inyecta con spring si son beans
public class UserResource {

    private final IUserService userService;

    @GetMapping("/users")
    public PagedModel<User> getUsers(){
        List<User> users = userService.getUsers();
        PagedModel.PageMetadata pageMetadata = new PagedModel.PageMetadata(users.size(),users.size(),1);
        return PagedModel.of(users,pageMetadata);
    }

    @GetMapping("/users/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username") String username){
        return ResponseEntity.ok(userService.getUser(username));
    }

    @PostMapping("/users")
    public ResponseEntity<User> saveUser(@RequestBody User user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users/"+user.getName()).toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/roles")
    public ResponseEntity<Role> saveRole(@RequestBody Role role){
        return ResponseEntity.ok(userService.saveRole(role));
    }

    @PutMapping("/users/{username}/roles/{role}")
    public ResponseEntity<User> addRoleToUser(@PathVariable("username") String userName,
                                              @PathVariable("role") String role){
        return ResponseEntity.ok(userService.addRoleToUser(userName,role));
    }





}

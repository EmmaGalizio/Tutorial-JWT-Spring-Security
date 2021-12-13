package emma.galzio.tutorialjwtspringsecurity.controller;

import emma.galzio.tutorialjwtspringsecurity.domain.Role;
import emma.galzio.tutorialjwtspringsecurity.domain.User;

import java.util.List;

public interface IUserService {

    User saveUser(User user);
    Role saveRole(Role role);
    User addRoleToUser(String userName, String roleName);
    User getUser(String userName);
    List<User> getUsers();
}

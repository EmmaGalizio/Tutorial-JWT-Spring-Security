package emma.galzio.tutorialjwtspringsecurity.repository;

import emma.galzio.tutorialjwtspringsecurity.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUserName(String userName);
}

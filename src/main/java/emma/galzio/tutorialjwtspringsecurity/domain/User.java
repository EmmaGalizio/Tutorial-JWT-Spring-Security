package emma.galzio.tutorialjwtspringsecurity.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

//Spring security tiene una clase llamada User, hay que tener cuidado con cual se importa

/**
 * @Data is a convenient shortcut annotation that bundles the features of @ToString,
 * @EqualsAndHashCode, @Getter / @Setter and @RequiredArgsConstructor together: In other words,
 * @Data generates all the boilerplate that is normally associated with simple POJOs (Plain Old Java Objects) and
 * beans: getters for all fields, setters for all non-final fields, and appropriate toString, equals and hashCode
 * implementations that involve the fields of the class, and a constructor that initializes all final fields,
 * as well as all non-final fields with no initializer that have been marked with @NonNull, in order to ensure the field is never null.
 */
@Entity
@Table
@Data @NoArgsConstructor @AllArgsConstructor
//@Data agrega los setters y getters, @NoArgsConstructor y @AllArgsConstructor agregan constructores
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String userName;
    private String password;
    @ManyToMany(fetch = FetchType.EAGER)
    private List<Role> roles;

    public void addRole(Role newRole){
        if(roles == null) roles = new ArrayList<>();
        //for(Role role: roles){

        //}
        roles.add(newRole);
    }

}

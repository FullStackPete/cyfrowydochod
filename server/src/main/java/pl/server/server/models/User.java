package pl.server.server.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.util.List;

@Entity
@Table(name="users")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode
@Builder
public class User {
    @Id
    @UuidGenerator
    private String id;
    private String username;
    private String email;
    private String password;
    private String refreshToken;
    private String role;
    private String token;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<Order> orders;

    @OneToOne(mappedBy = "user", fetch = FetchType.LAZY)
    private BillingAddress billingAddress;

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
}

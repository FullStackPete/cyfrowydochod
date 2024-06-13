package pl.server.server.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

@Entity
@Table(name = "ticket")
@Getter
@Setter
@Builder
@EqualsAndHashCode
public class Ticket {
    @Id
    @UuidGenerator
    private String id;
    private String text;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

}
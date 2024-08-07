package pl.server.server.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import pl.server.server.models.BillingAddress;
@Repository
public interface BillingAddressRepository extends JpaRepository<BillingAddress,String> {
    Optional<BillingAddress> findByUserId(String userId);
}

package pl.server.server.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.server.server.helpers.ResourceNotFoundException;
import pl.server.server.models.User;
import pl.server.server.services.UserService;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@Component(value = "userController")
public class UserController {

    @Autowired
    UserService userService;


    @PutMapping("/id/{id}")
    public ResponseEntity<String> updateUser(@PathVariable String id, @RequestBody User updatedUser,
            HttpServletRequest request) {
                System.out.println("Updating user");
        return userService.updateUser(id, updatedUser, request);
    }

    @DeleteMapping("/id/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable String id, @RequestBody String password) {
        try {
            userService.deleteUser(id, password);
            return ResponseEntity.ok().build();
        } catch (ResourceNotFoundException notFoundException) {
            return ResponseEntity.notFound().build();
        } catch (RuntimeException exception) {
            System.err.println(exception);
            return ResponseEntity.badRequest().build();
        }
    }

}

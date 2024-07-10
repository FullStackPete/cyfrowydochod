package pl.server.server.services;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import pl.server.server.DTOs.LoginRequest;
import pl.server.server.DTOs.RegistrationRequest;
import pl.server.server.config.JwtAuthenticationFilter;
import pl.server.server.config.JwtTokenProvider;
import pl.server.server.models.User;
import pl.server.server.models.UserPreferences;
import pl.server.server.models.UserRole;
import pl.server.server.repositories.UserPreferencesRepository;
import pl.server.server.repositories.UserRepository;

@Service
@Validated
public class AuthService {

    @Autowired
    private UserPreferencesRepository userPreferencesRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider tokenProvider;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    public ResponseEntity<String> loginUser(LoginRequest loginRequest, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()));
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = (User) userRepository.findByEmail(loginRequest.getEmail());
            String username = user.getUsername();
            UserPreferences userPrefs = userPreferencesRepository.findByUserId(user.getId());
            String jwtAccessToken = tokenProvider.generateToken(userDetails, user.getId(), user.getEmail(),
                    user.getRole(), username, "accessToken",userPrefs);
            String jwtRefreshToken = tokenProvider.generateToken(userDetails, user.getId(), user.getEmail(),
                    user.getRole(), username, "refreshToken",userPrefs);
            user.setRefreshToken(jwtRefreshToken);
            userRepository.save(user);

            Cookie refreshTokenCookie = createRefreshTokenCookie(response, "refreshToken", true, false,
                    jwtRefreshToken);
            response.addCookie(refreshTokenCookie);

            return ResponseEntity.ok(jwtAccessToken);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
        }
    }

    public Cookie createRefreshTokenCookie(HttpServletResponse response, String name, boolean httpOnly,
            boolean secureFlag, String token) {

        Cookie cookie = new Cookie(name, token);
        cookie.setHttpOnly(httpOnly);
        cookie.setMaxAge(86400); // 1 day
        cookie.setSecure(secureFlag); // Use true in production with HTTPS
        cookie.setPath("/");
        return cookie;
    }

    public ResponseEntity<String> registerUser(@Valid RegistrationRequest registrationRequest) {
        try{
            UserRole userRole = new UserRole();
    
            @Size(min = 2, max = 20, message = "Username size is not between 2 and 20")
            String newUserUsername = registrationRequest.getUsername();
            @Size(min = 4, max = 30, message = "Password size is not between 4 and 30")
            String newUserPass = registrationRequest.getPassword();
            @Email
            String newUserEmail = registrationRequest.getEmail();
    
            if (userRepository.findByEmail(newUserEmail).isPresent()) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Email is taken!");
            }
            if (!userRepository.findByUsername(newUserUsername).isEmpty()) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Username is taken!");
            }
            User user = new User();
            UserPreferences userPrefs = new UserPreferences();
            userPrefs.setAvatar("axolotl");
            userPrefs.setGetNewsLetter(false);
            userPrefs.setGetPriceDrops(false);
            userPrefs.setGetTrendingEbooks(false);
            userPrefs.setDarkMode(false);
            userPrefs.setUser(user); // Set user in preferences
    
            user.setUserPreferences(userPrefs);
            user.setEmail(newUserEmail);
            user.setUsername(newUserUsername);
            user.setPassword(passwordEncoder.encode(newUserPass));
            user.setRole(userRole.getUserRole());
    
            userRepository.save(user);
    
            return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully!");

        } catch(Exception ex){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Exception thrown:" + ex);
        }
    }

    public ResponseEntity<String> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {

        try {
            String refreshToken = getRefreshTokenFromCookie(request);
            System.out.println("refreshToken:" + refreshToken);
            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token missing");
            }

            String userId = jwtAuthenticationFilter.getUserIdFromToken(refreshToken);
            User user = userRepository.findById(userId).orElse(null);

            if (user == null || !user.getRefreshToken().equals(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
            }

            if (jwtAuthenticationFilter.isTokenExpired(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token expired");
            }

            UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getEmail(),
                    user.getPassword(), new ArrayList<>());
                    UserPreferences userPreferences = userPreferencesRepository.findByUserId(userId);
            String newAccessToken = tokenProvider.generateToken(userDetails, user.getId(), user.getEmail(),
                    user.getRole(), user.getUsername(), "accessToken",userPreferences);

            return ResponseEntity.ok(newAccessToken);

        } catch (Exception e) {
            System.err.println(e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
    }

    public ResponseEntity<String> handleLogOut(HttpServletRequest request, HttpServletResponse response) {
        String token = getRefreshTokenFromCookie(request);
        if (token == null) {
            return ResponseEntity.noContent().build();
        }
        String userId = jwtAuthenticationFilter.getUserIdFromToken(token);
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            Cookie emptyCookie = createEmptyCookie();
            response.addCookie(emptyCookie);
            return ResponseEntity.noContent().build();
        }
        user.setRefreshToken("");
        userRepository.save(user);
        Cookie emptyCookie = createEmptyCookie();
        response.addCookie(emptyCookie);
        return ResponseEntity.noContent().build();
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public Cookie createEmptyCookie() {
        Cookie cookie = new Cookie("refreshToken", "");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(86400); // 1 day
        cookie.setSecure(false); // Use true in production with HTTPS
        cookie.setPath("/");
        return cookie;
    }

    public boolean verifyUserPassword(String password, String userId) {
        User user = userRepository.findById(userId).orElse(null);
        System.out.println("User found:" +user);
        if (user == null) {
            System.out.println("User not found!");
            return false;
            
        }
        System.out.println("Trying to match passwords...");
        return passwordEncoder.matches(password, user.getPassword());
    }

}

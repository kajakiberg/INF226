package no.bufferoverflow.inshare;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
@Configuration
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Adjust as needed
                .authorizeHttpRequests(authz -> authz
                                .requestMatchers("/register","register.html","/public","/style.css","/").permitAll() // Public access to static resources and registration
                                .anyRequest().authenticated() // All other requests require authentication
                )
                .formLogin(login -> login.permitAll()); // Allow form-based login

        return http.build();
    }
    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }
}

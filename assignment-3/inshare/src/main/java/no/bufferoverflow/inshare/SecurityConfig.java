package no.bufferoverflow.inshare;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
@Configuration
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    private final AccessDeniedHandler customAccessDeniedHandler;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService, AccessDeniedHandler customAccessDeniedHandler) {
        this.userDetailsService = userDetailsService;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //.csrf(csrf -> csrf.disable()) // Adjust as needed
                .csrf(csrf -> csrf.ignoringRequestMatchers("/register"))
                .authorizeHttpRequests(authz -> authz
                                .requestMatchers("/register","register.html","/public","/style.css","/").permitAll() // Public access to static resources and registration
                                .anyRequest().authenticated() // All other requests require authentication
                )
                .formLogin(login -> login.permitAll()) // Allow form-based login
                .exceptionHandling()
                .accessDeniedHandler(customAccessDeniedHandler); // Use custom handler

        return http.build();
    }
    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

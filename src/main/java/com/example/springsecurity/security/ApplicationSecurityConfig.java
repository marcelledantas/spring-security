package com.example.springsecurity.security;

import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

//    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
//        this.passwordEncoder = passwordEncoder;
//    }

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.
        csrf().disable().
                authorizeHttpRequests((authorize ) -> authorize
                                .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                        .requestMatchers( "index", "/", "/js/*", "/css/*").permitAll()
                        .requestMatchers("/api/**").hasRole(ApplicationUserRole.ADMIN.name())
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        UserDetails userAnna = User.builder()
                .username("Anna")
                .password(passwordEncoder.encode("password"))
                .roles(ApplicationUserRole.ADMIN.name())
                .build();


        UserDetails userLinda = User.builder()
                .username("Linda")
                .password(passwordEncoder.encode("password"))
                .roles(ApplicationUserRole.STUDENT.name())
                .build();

        UserDetails userTom= User.builder()
                .username("Tom")
                .password(passwordEncoder.encode("password"))
                .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(userAnna, userLinda, userTom);
    }

}

package com.yzn.securitydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration // --> Tells Spring that this class provides configuration to the application context
@EnableWebSecurity // --> Tells Spring Boot to enable web security features in the application
@EnableMethodSecurity
public class SecurityConfig {

    @Bean // --> Mark this as bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Any request will be authenticated by default
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        http.sessionManagement(session
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // -> Requests are now stateless
        //http.formLogin(withDefaults());
        // Configures basic authentication, and it specifies that Spring Security should use HTTP Basic Authentication with default settings
        http.httpBasic(withDefaults()); // --> If disabled formLogin, it will show an alert before accessing the endpoint
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}password1")
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}adminPass")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1,admin);
    }
}

package com.yzn.securitydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration // --> Tells Spring that this class provides configuration to the application context
@EnableWebSecurity // --> Tells Spring Boot to enable web security features in the application
@EnableMethodSecurity
public class SecurityConfig {

    DataSource dataSource;

    public SecurityConfig(DataSource dataSource){
        this.dataSource = dataSource;
    }

    @Bean // --> Mark this as bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Any request will be authenticated by default
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated());
        http.sessionManagement(session
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // -> Requests are now stateless
        //http.formLogin(withDefaults());
        // Configures basic authentication, and it specifies that Spring Security should use HTTP Basic Authentication with default settings
        http.httpBasic(withDefaults()); // --> If disabled formLogin, it will show an alert before accessing the endpoint
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("adminPass"))
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;
        // In Memory
        // return new InMemoryUserDetailsManager(user1,admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}

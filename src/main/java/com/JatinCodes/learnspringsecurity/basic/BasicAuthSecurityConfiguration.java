package com.JatinCodes.learnspringsecurity.basic;
/**
 * There are 2 approaches to Spring Security Authorization:
 * 1. Global Security
 * 2. Method Security
 *
 */

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration // we are using JWT now so .. commented it out.
@EnableMethodSecurity(jsr250Enabled = true,securedEnabled = true)  // It is Method Security
public class BasicAuthSecurityConfiguration {

    @Bean  // the below function is taken from SpringBootWebSecurityConfiguration.java file
    SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                auth -> {
                    auth
                            .requestMatchers("/users").hasRole("USER") // providing Authorization // This is called Global Security
                            .requestMatchers("/admin/**").hasRole("ADMIN")
                            .anyRequest().authenticated();
                });
        // spring security will never create a http session
        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        // http.formLogin(); // commenting it out : logout and login page not there , pop up is there for login page
        http.httpBasic();
        // disable csrf
        http.csrf().disable();
        http.headers().frameOptions().sameOrigin(); // this will disable frames , and h2-console will work
        return http.build();
    }

//    @Bean  // the below function uses in-memory database to save credentials
//    public UserDetailsService userDetailService() {
//
//        // USER 1
//        var user = User.withUsername("in28minutes")
//                .password("{noop}dummy")   // noop -> used to say no encoding needed
//                .roles("USER")
//                .build();
//
//        // USER 2
//        var admin = User.withUsername("admin")
//                .password("{noop}dummy")
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user,admin);
//    }

    @Bean // this will create our own datasource
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsService userDetailService(DataSource dataSource) {

        var user = User.withUsername("in28minutes")
                //.password("{noop}dummy") // noop -> used to say no encoding needed
                .password("dummy")
                .passwordEncoder( str -> passwordEncoder().encode(str))  // now password is encoded
                .roles("USER")
                .build();

        var admin = User.withUsername("admin")
                //.password("{noop}dummy")
                .password("dummy")
                .passwordEncoder( str -> passwordEncoder().encode(str))
                .roles("ADMIN", "USER")
                .build();

        // jdbcUserDetailsManager is a predefined java module to store the user credentials in jdbc
        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean  // one way hash function -> only encrypts , don't decrypt
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

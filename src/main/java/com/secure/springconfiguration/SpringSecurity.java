package com.secure.springconfiguration;

import com.secure.jwt.AuthEntryPointJwt;
import com.secure.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//import jakarta.validation.constraints.Pattern;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity //used for role assigning (@PreAuthorize())
public class SpringSecurity {
	
	@Autowired
	DataSource datasource;

	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;

	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		//we're directly giving access to h2-console without entering any credentials
		http.authorizeHttpRequests(auth->auth.requestMatchers("/h2-console/**").permitAll()
				.requestMatchers("/signin").permitAll().anyRequest().authenticated());
		http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		Customizer<HttpBasicConfigurer<HttpSecurity>> withDefaults;
//		http.httpBasic(withDefaults());
		//below frame for h2-console
		http.headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
		http.csrf(csrf->csrf.disable());
		http.addFilterBefore(authenticationJwtTokenFilter(),
				UsernamePasswordAuthenticationFilter.class);
		return http.build();		
	}
	/*
	first code
	@Bean
	public UserDetailsService userDetailsService() {
		//Managing users inmemory
//		UserDetails user1=User.withUsername("user1").password("{noop}password").roles("User").build();
//		UserDetails admin=User.withUsername("admin1").password("{noop}adminPass").roles("Admin").build();
		// for encryption below we will use
		UserDetails user1=User.withUsername("user1").password(passwordEncoder().encode("password")).roles("User").build();//password will store like this: $2a$10$RRrYCPl7im1QGb7oFYJPY.JrUt4sc0/h6wO7ZlA1pyme0CIZXxQNa	
		UserDetails admin=User.withUsername("admin1").password(passwordEncoder().encode("adminPass")).roles("Admin").build();
//		return new InMemoryUserDetailsManager(user1,admin); here it will not store in db, credentials will store in inmemory
		//in the place of InMemoryUserDetailsManager we will JDBCUserDetailsManager to store credentials in database
		
		JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager(datasource);
		userDetailsManager.createUser(user1);
		userDetailsManager.createUser(admin);
		return userDetailsManager;
		
	}
	*/

	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}


	@Bean
	public CommandLineRunner initData(UserDetailsService userDetailsService) {
		return args -> {
			JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
			UserDetails user1 = User.withUsername("user1")
					.password(passwordEncoder().encode("password1"))
					.roles("User")
					.build();
			UserDetails admin = User.withUsername("admin1")
					//.password(passwordEncoder().encode("adminPass"))
					.password(passwordEncoder().encode("adminPass"))
					.roles("Admin")
					.build();

			JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(datasource);
			userDetailsManager.createUser(user1);
			userDetailsManager.createUser(admin);
		};
	}


	// below steps for encrypting the password
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
	}

}

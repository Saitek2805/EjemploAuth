package com.example.demo.configuracion;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.example.demo.servicio.usuario.UsuarioPersonalizadoDetailsService;



@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
	 @Autowired
	 private UsuarioPersonalizadoDetailsService userDetailsService;

	@Bean
	public  SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {
       
		  AuthenticationManager authentication = authenticationConfiguration.getAuthenticationManager();
		  if (authentication != null) {
	        http.addFilterBefore(new FiltroDeAutenticacionPersonalizado(authentication), BasicAuthenticationFilter.class)
	        .authorizeHttpRequests((authorize) -> authorize
		       .requestMatchers("/admin/**").hasRole("ADMIN")  // Rutas bajo "/admin/" requieren el rol ADMIN
		       .requestMatchers("/user/**").hasRole("USER")    // Rutas bajo "/user/" requieren el rol USER
		       .requestMatchers("/login","/", "/home", "/crear", "/public/**").permitAll() // Permite el acceso a estas rutas sin autenticación
		       .anyRequest().authenticated() // Cualquier otra solicitud requiere autenticación
	        
	        ).userDetailsService(userDetailsService)
	        .oauth2Login(oauth2 -> oauth2.loginPage("/login").successHandler(new CustomAuthenticationSuccessHandler())
	               
	            )
		   // Configuración para el proceso de inicio de sesión
	       .formLogin(formLogin -> 
            formLogin
                .loginPage("/login")  // URL personalizada de inicio de sesión
                .successHandler(new CustomAuthenticationSuccessHandler())  // Usa el manejador personalizado                        
                .permitAll())
	       // Configuración para el proceso de cierre de sesión
	        .logout(logout -> 
            logout.logoutSuccessUrl("/login?logout")
            .invalidateHttpSession(true)       // Invalida la sesión actual
            .clearAuthentication(true)        // Limpia la autenticación
            .deleteCookies("JSESSIONID")      // Borra la cookie de sesión (opcional)
            .permitAll());
		  }
	    return http.build();
	}
	 @Bean
	    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
	        return authenticationConfiguration.getAuthenticationManager();
	    }
	@Bean
	public PasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
	/*
	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
	    return new UsuarioGoogleOAuth2UserService();
	}*/
}
	/**
	 * En memoria
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.builder()
		        .username("user")
		        .password(passwordEncoder().encode("user"))
		        .roles("USER") // Roles se especifican aquí
		        .build();

		    UserDetails admin = User.builder()
		        .username("admin")
		        .password(passwordEncoder().encode("admin"))
		        .roles("ADMIN") // Roles se especifican aquí
		        .build();

		return new InMemoryUserDetailsManager(user, admin);
	}*/
	





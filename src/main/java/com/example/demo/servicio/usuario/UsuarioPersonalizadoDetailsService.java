package com.example.demo.servicio.usuario;

import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.entidad.Usuario;
import com.example.demo.repositorio.UsuarioRepository;

import jakarta.transaction.Transactional;

/**
 * Este servicio se utiliza para cargar los detalles del usuario 
 * durante la autenticación y la autorización 
 * en aplicaciones basadas en Spring Security.
 */
@Service
public class UsuarioPersonalizadoDetailsService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    /**
     * Carga los detalles de un usuario por su nombre de usuario.
     *
     * Este método se utiliza en el proceso de autenticación de Spring Security.
     * Se encarga de recuperar los detalles del usuario desde la base de datos
     * (o cualquier otro medio de persistencia) utilizando el `UsuarioRepository`.
     *
     * @param username El nombre de usuario del usuario a autenticar.
     * @return UserDetails Una implementación de UserDetails que contiene la información del usuario.
     * @throws UsernameNotFoundException Si el usuario con el nombre de usuario dado no se encuentra.
     *
     * El flujo del método es el siguiente:
     * 1. Intenta encontrar un usuario en la base de datos por su nombre de usuario.
     * 2. Si el usuario no se encuentra, lanza una UsernameNotFoundException.
     * 3. Si se encuentra el usuario, construye y devuelve un objeto User (que implementa UserDetails)
     *    con el nombre de usuario, contraseña y autoridades (roles) del usuario.
     *    - La conversión de los roles del usuario a autoridades de Spring Security
     *      se realiza mapeando cada rol a un SimpleGrantedAuthority.
     */
	@Override
    @Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		 
		
		Usuario usuario = usuarioRepository.findByUsername(username)
	                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

	       return new User(usuario.getUsername(), usuario.getPassword(), 
	                usuario.getRoles().stream()
	                        .map(rol -> new SimpleGrantedAuthority(rol.toString()))
	                        .collect(Collectors.toList()));
	}


}




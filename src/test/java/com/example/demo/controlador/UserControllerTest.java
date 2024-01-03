package com.example.demo.controlador;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.example.demo.dto.UsuarioDTO;
import com.example.demo.entidad.Comentario;
import com.example.demo.entidad.Usuario;
import com.example.demo.servicio.comentario.ComentarioServicio;
import com.example.demo.servicio.usuario.UsuarioServicio;

@WebMvcTest(UserController.class)
public class UserControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ComentarioServicio comentarioServicio;

	@MockBean
	private UsuarioServicio usuarioServicio;

	@InjectMocks
	private UserController userController;

	@Autowired
	private WebApplicationContext webApplicationContext;

	@BeforeEach
	public void setup() {
		
		/**
		 *  Construir una instancia de MockMvc. 
		 *  Esto es crucial para simular peticiones HTTP 
		 *  a tu controlador en un entorno de prueba aislado.
		 */
		mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
				.apply(springSecurity()) // Asegúrate de aplicar la seguridad de Spring
				.build();

	    /** 
	     * Configurar un objeto Page<Comentario> no nulo para evitar NullPointerException
	     */
		Page<Comentario> comentariosPage = new PageImpl<>(Collections.emptyList(), PageRequest.of(0, 10), 0);
		when(comentarioServicio.listarTodos(any(PageRequest.class))).thenReturn(comentariosPage);
		/**
		 * UsuarioDTO mockeado 
		 * para ser devuelto por usuarioServicio.obtenerUsuarioDTO.
		 */
		 UsuarioDTO usuariodtoMock = new UsuarioDTO();
		 usuariodtoMock.setUsername("user");
		 usuariodtoMock.setId(1L);
		    // ... set other properties of usuarioMock as needed
		    when(usuarioServicio.obtenerUsuarioDTO(anyString())).thenReturn(usuariodtoMock);
		
		    // Configura el comportamiento esperado para el servicio de usuario.
		    Usuario usuarioMock = new Usuario();
		    usuarioMock.setId(1L); // Suponiendo que el ID del usuario es 1
		    when(usuarioServicio.obtenerPorId(anyLong())).thenReturn(usuarioMock);  
		    
		/**
		 * Simular un contexto de seguridad con un usuario autenticado. 
		 * Esto es esencial para pruebas que dependen de la autenticación 
		 * y autorización de Spring Security.
		 */
		Authentication authentication = mock(Authentication.class);
		when(authentication.getName()).thenReturn("user");
		SecurityContext securityContext = mock(SecurityContext.class);
		when(securityContext.getAuthentication()).thenReturn(authentication);
		SecurityContextHolder.setContext(securityContext);
	}


	@Test
	@WithMockUser(username = "user", roles = "USER")
	public void testMostrarFormularioComentario() throws Exception {
	    mockMvc.perform(get("/user/agregarComentario"))
	           .andExpect(status().isOk())
	           .andExpect(view().name("/auth/user/formCrearComentario"))
	           .andExpect(model().attributeExists("comentario"))
	           // Aquí puedes añadir más aserciones si el método añade más atributos al modelo
	           ;
	}
	
	@Test
	@WithMockUser(username = "user", roles = "USER")
	public void testAgregarComentario() throws Exception {
		// Simula una solicitud POST al controlador
	    mockMvc.perform(post("/user/agregarComentario")
	                    .param("texto", "Este es un comentario de prueba")
	                    .param("usuarioId", "1") // Asegúrate de que estos parámetros sean los esperados por el controlador
	                    .with(csrf())) // Importante para formularios POST
	           .andExpect(status().isOk());
	          
      
	}
	
	@Test
	@WithMockUser
	public void testMostrarFormularioDeCreacion() throws Exception {
	    mockMvc.perform(get("/crear"))
	           .andExpect(status().isOk())
	           .andExpect(view().name("public/formCrearUsuario"))
	           
	           .andExpect(model().attributeExists("usuario"));
	}
	@Test
	@WithMockUser
	public void testCrearUsuario() throws Exception {
	    // Datos de prueba
	    String username = "nuevoUsuario";
	    String password = "contraseñaSegura123";
	    String email = "nuevo@correo.com";
	    String nombre = "Nuevo";
	    String apellido = "Usuario";

	    // Simula una solicitud POST al endpoint /crear
	    mockMvc.perform(post("/crear")
	                    .param("username", username)
	                    .param("password", password)
	                    .param("perfilusuario.email", email)
	                    .param("perfilusuario.nombre", nombre)
	                    .param("perfilusuario.apellido", apellido)
	                    .with(csrf()))
	           .andExpect(status().is3xxRedirection())
	           .andExpect(redirectedUrl("/"));
	    
	    // Verificar que el método guardar del servicio fue llamado
	    verify(usuarioServicio, times(1)).guardar(any(Usuario.class));
	}
}

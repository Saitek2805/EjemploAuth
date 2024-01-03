package com.example.demo.controlador;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.demo.entidad.Comentario;
import com.example.demo.entidad.PerfilUsuario;
import com.example.demo.entidad.Usuario;
import com.example.demo.entidad.enumerado.RolUsuario;
import com.example.demo.servicio.comentario.ComentarioServicio;
import com.example.demo.servicio.usuario.UsuarioServicio;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;



@Controller
public class MainController {
	
    private static final Logger logger = LoggerFactory.getLogger(MainController.class);

	 @Autowired
	 private ComentarioServicio comentarioServicio;
	 
	 @Autowired
	 private UsuarioServicio usuarioServicio;


    @GetMapping("/")
    public String index() {
    	logger.info("@ INFO :: ### Acceso a Página Index . ###");
    	logger.error("@ ERROR :: example ");
    	logger.warn("@ WARNING :: example ");
    
        return "index"; // Muestra la página de inicio (index.html)
    }	

    @GetMapping("/login")
    public String showLoginForm(Model model, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        boolean isLoggedIn = (session != null && session.getAttribute("SPRING_SECURITY_CONTEXT") != null);
        model.addAttribute("isLoggedIn", isLoggedIn);
        return "public/login"; // Nombre de tu plantilla de inicio de sesión
    }
    
    @GetMapping("/oauth")
    public String showPageOauth(Model model, HttpServletRequest request, Authentication authentication) {
    	if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            // Extrae la información necesaria del objeto OAuth2User

            Map<String, Object> attributes = oAuth2User.getAttributes();

            model.addAttribute("attributes", attributes);

            return "auth/oauth/home";
        } else {
            // Manejar otros casos o lanzar una excepción
            return "error"; // Redirigir a una página de error o manejar de otra manera
        }
    }
    

@GetMapping("/home")
public String home(Model model,  
		@RequestParam(value = "page", defaultValue = "0") int page, /* PAGINACIÓN */
        @RequestParam(value = "size", defaultValue = "5") int size, /* PAGINACIÓN */
         HttpServletRequest request ) {

	//Obtener { Comentarios } ordenar por fecha de creación
    PageRequest pageRequest = PageRequest.of(page, size,Sort.by("fechaCreacion").descending());
    Page<Comentario> comentarios = comentarioServicio.listarTodos(pageRequest);

    model.addAttribute("comentarios", comentarios);


    return "public/home";


}


@GetMapping("/crear")
public String mostrarFormularioDeCreacion(Model model) {
    Usuario usuario = new Usuario();
    usuario.setPerfilusuario(new PerfilUsuario()); // Inicializa el perfil del usuario
    model.addAttribute("usuario", usuario);
    return "public/formCrearUsuario";
}

@PostMapping("/crear")
public String crearUsuario(@Valid @ModelAttribute("usuario") Usuario usuario, BindingResult result, Model model) {
   
	if (result.hasErrors()) {
        return "public/formCrearUsuario";
    }

	usuario.getRoles().add(RolUsuario.ROLE_USER);

    usuarioServicio.guardar(usuario); // Guarda el usuario y el perfil asociado
    logger.info("Usuario creado con éxito: {}", usuario.getUsername());
    return "redirect:/"; 
}
}
package com.example.demo.controlador;

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

/**
 * Controlador principal de la aplicación.
 * 
 * <p>Este controlador maneja las solicitudes relacionadas con la página de inicio,
 * el inicio de sesión, la visualización de comentarios y la creación de usuarios.</p>
 * 
 * @version 1.0
 */
@Controller
public class MainController {

    private static final Logger logger = LoggerFactory.getLogger(MainController.class);

    @Autowired
    private ComentarioServicio comentarioServicio;

    @Autowired
    private UsuarioServicio usuarioServicio;

    /**
     * Maneja las solicitudes GET a la URL raíz ("/").
     * 
     * <p>Este método muestra la página de inicio de la aplicación.</p>
     * 
     * @return el nombre de la vista para la página de inicio
     */
    @GetMapping("/")
    public String index() {
        logger.info("@ INFO :: ### Acceso a Página Index . ###");
        logger.error("@ ERROR :: example ");
        logger.warn("@ WARNING :: example ");
    
        return "index"; // Muestra la página de inicio (index.html)
    }

    /**
     * Maneja las solicitudes GET a la URL "/login".
     * 
     * <p>Este método muestra el formulario de inicio de sesión.</p>
     * 
     * @param model el modelo para la vista
     * @param request la solicitud HTTP
     * @return el nombre de la vista para el formulario de inicio de sesión
     */
    @GetMapping("/login")
    public String showLoginForm(Model model, HttpServletRequest request) {
    	
        HttpSession session = request.getSession(false);
        boolean isLoggedIn = (session != null && session.getAttribute("SPRING_SECURITY_CONTEXT") != null);
        model.addAttribute("isLoggedIn", isLoggedIn);
       // logger.info("@ INFO :: ### Acceso a inicio de sesion . ###");
        return "public/login"; // Nombre de tu plantilla de inicio de sesión
    }

    /**
     * Maneja las solicitudes GET a la URL "/home".
     * 
     * <p>Este método muestra la página de inicio para usuarios registrados, 
     * con la lista de comentarios paginada.</p>
     * 
     * @param model el modelo para la vista
     * @param page el número de página para la paginación
     * @param size el tamaño de la página para la paginación
     * @param request la solicitud HTTP
     * @return el nombre de la vista para la página de inicio
     */
    @GetMapping("/home")
    public String home(Model model,  
                      @RequestParam(value = "page", defaultValue = "0") int page, /* PAGINACIÓN */
                      @RequestParam(value = "size", defaultValue = "5") int size, /* PAGINACIÓN */
                      HttpServletRequest request) {

        // Obtener { Comentarios } ordenar por fecha de creación
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("fechaCreacion").descending());
        Page<Comentario> comentarios = comentarioServicio.listarTodos(pageRequest);

        model.addAttribute("comentarios", comentarios);

        return "public/home";
    }

    /**
     * Maneja las solicitudes GET a la URL "/crear".
     * 
     * <p>Este método muestra el formulario para la creación de un nuevo usuario.</p>
     * 
     * @param model el modelo para la vista
     * @return el nombre de la vista para el formulario de creación de usuario
     */
    @GetMapping("/crear")
    public String mostrarFormularioDeCreacion(Model model) {
        Usuario usuario = new Usuario();
        usuario.setPerfilusuario(new PerfilUsuario()); // Inicializa el perfil del usuario
        model.addAttribute("usuario", usuario);
        return "public/formCrearUsuario";
    }

    /**
     * Maneja las solicitudes POST a la URL "/crear".
     * 
     * <p>Este método procesa la creación de un nuevo usuario.</p>
     * 
     * @param usuario el usuario a crear
     * @param result el resultado de la validación del formulario
     * @param model el modelo para la vista
     * @return la redirección a la página de inicio si el usuario es creado con éxito
     */
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
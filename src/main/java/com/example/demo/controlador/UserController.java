package com.example.demo.controlador;

import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.demo.dto.UsuarioDTO;
import com.example.demo.entidad.Comentario;
import com.example.demo.entidad.PerfilUsuario;
import com.example.demo.entidad.Usuario;
import com.example.demo.servicio.comentario.ComentarioServicio;
import com.example.demo.servicio.usuario.UsuarioServicio;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@Controller
@RequestMapping("/user")
public class UserController {

    @Autowired
    private ComentarioServicio comentariosServicio;

    @Autowired
    private UsuarioServicio usuarioServicio;

    private static final String HOME = "auth/user/home";

    /**
     * Maneja las solicitudes GET a la URL "/user/home".
     * 
     * <p>Este método muestra la página de inicio para los usuarios registrados,
     * con la lista de comentarios paginada y opciones de filtrado.</p>
     * 
     * @param model el modelo para la vista
     * @param authentication la autenticación del usuario
     * @param page el número de página para la paginación
     * @param size el tamaño de la página para la paginación
     * @param username el nombre de usuario para filtrar los comentarios
     * @param palabraClave la palabra clave para buscar en los comentarios
     * @param request la solicitud HTTP
     * @return el nombre de la vista para la página de inicio del usuario
     */
    @GetMapping("/home")
    @PreAuthorize("hasRole('USER')")
    public String user(Model model, Authentication authentication,
                       @RequestParam(value = "page", defaultValue = "0") int page,
                       @RequestParam(value = "size", defaultValue = "5") int size,
                       @RequestParam(required = false) String username,
                       @RequestParam(required = false) String palabraClave,
                       HttpServletRequest request) {

        String usernameAuth = authentication.getName(); // Obtener el nombre de usuario del objeto de autenticación
        model.addAttribute("username", usernameAuth); // Agregarlo al modelo

        UsuarioDTO usuarioDTO = usuarioServicio.obtenerUsuarioDTO(usernameAuth);
        model.addAttribute("usuarioDTO", usuarioDTO);

        // Para el <Select>Usuario</Select>
        model.addAttribute("usuarios", comentariosServicio.obtenerUsuariosConComentarios());

        // Para crear <form>Comentarios </form>
        model.addAttribute("comentario", new Comentario());
        
        /**
         * #######################
         * ##    PÁGINACIÓN     ##
         * #######################	 
         */
        // Configuración de paginación
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("fechaCreacion").ascending());
        Page<Comentario> comentarios;

        // Manejar errores si username o palabraClave son nulos o vacíos
        if (username == null) {
            username = "";
        }
        if (palabraClave == null) {
            palabraClave = "";
        }

        if (!palabraClave.isEmpty()) {
            comentarios = comentariosServicio.buscarPorPalabraClave(pageRequest, palabraClave);
            System.out.println("#COMENTARIOS CON PALABRA CLAVE '" + palabraClave + "': " + comentarios);
        } else if (!username.isEmpty() && usuarioServicio.existe(username)) {
            comentarios = comentariosServicio.listarFiltroPorUsuario(pageRequest, username);
            System.out.println("#COMENTARIOS DE USUARIO '" + username + "': " + comentarios);
        } else {
            comentarios = comentariosServicio.listarTodos(pageRequest);
            System.out.println("#COMENTARIOS TOTALES: " + comentarios);
        }

        try {
            PerfilUsuario perfilUsuario = usuarioServicio.obtenerPorUsername(usernameAuth).getPerfilusuario();
            model.addAttribute("perfilUsuario", perfilUsuario);
        } catch (Exception e) {
            e.printStackTrace();
        }

        model.addAttribute("comentarios", comentarios);
        model.addAttribute("requestURI", request.getRequestURI());

        return HOME; // Muestra la página específica del usuario (user.html)
    }
    /**
     * #############################
     * ##<FORM> COMENTARIO</FORM> ##
     * #############################	 
     */
    /**
     * Maneja las solicitudes GET a la URL "/user/agregarComentario".
     * 
     * <p>Este método muestra el formulario para agregar un nuevo comentario.</p>
     * 
     * @param model el modelo para la vista
     * @return el nombre de la vista para el formulario de creación de comentarios
     */
    @GetMapping("/agregarComentario")
    @PreAuthorize("hasRole('USER')")
    public String mostrarFormularioComentario(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        UsuarioDTO usuarioDTO = usuarioServicio.obtenerUsuarioDTO(username);

        System.out.println("############# id:" + usuarioDTO.getId());

        // Crear una nueva instancia de Comentario y añadirla al modelo
        Comentario comentario = new Comentario();
        comentario.setFechaCreacion(LocalDateTime.now());
        model.addAttribute("comentario", comentario);
        model.addAttribute("usuarioDTO", usuarioDTO); // Añadir el UsuarioDTO al modelo si es necesario
        
        return "/auth/user/formCrearComentario";
    }

    /**
     * Maneja las solicitudes POST a la URL "/user/agregarComentario".
     * 
     * <p>Este método procesa la creación de un nuevo comentario asociado a un usuario.</p>
     * 
     * @param comentario el comentario a agregar
     * @param result el resultado de la validación del formulario
     * @param usuarioId el ID del usuario asociado al comentario
     * @param model el modelo para la vista
     * @return la redirección a la página de inicio del usuario si el comentario es creado con éxito
     */
    @PostMapping("/agregarComentario")
    @PreAuthorize("hasRole('USER')")
    public String agregarComentario(@Valid @ModelAttribute("comentario") Comentario comentario,
                                    BindingResult result,
                                    @RequestParam("usuarioId") Long usuarioId,
                                    Model model) {
        if (result.hasErrors()) {
            return "/auth/user/formCrearComentario";
        }
        // Busca el usuario por el ID capturado
        Usuario usuario = usuarioServicio.obtenerPorId(usuarioId);
        // Asocia el usuario al comentario
        comentario.setUsuario(usuario);

        System.out.println("## contenido ## " + comentario.toString());

        comentariosServicio.guardar(comentario);
        return "redirect:/user/home";
    }
}
	

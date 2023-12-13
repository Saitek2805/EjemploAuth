package com.example.demo.entidad;
import java.util.HashSet;
import java.util.Set;

import com.example.demo.entidad.enumerado.RolUsuario;

import jakarta.persistence.*;
import jakarta.validation.constraints.Size;

@Table(name = "Usuarios")
@Entity
public class Usuario {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true)
    private String username;
    
    @Size(min = 8) // Asumiendo que quieres una contraseña de al menos 8 caracteres
    private String password;
    
    @OneToMany(mappedBy = "usuario", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private Set<Comentario> comentarios = new HashSet<>();
 
    
    @OneToOne(mappedBy= "usuario", cascade = CascadeType.ALL)
    private PerfilUsuario perfilusuario;
    
    @ElementCollection(targetClass = RolUsuario.class) //Instrucción de Hibernate para que guarde colecciones enumeradas
    @Enumerated(EnumType.STRING)
    @CollectionTable(name="usuario_rol")
    @Column(name ="RolesUsuario")
    private Set<RolUsuario> roles = new HashSet<>();
    
    // Getters y setters
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Set<RolUsuario> getRoles() {
		return roles;
	}

	public void setRoles(Set<RolUsuario> roles) {
		this.roles = roles;
	}

	public Set<Comentario> getComentarios() {
		return comentarios;
	}

	public void setComentarios(Set<Comentario> comentarios) {
		this.comentarios = comentarios;
	}

	public PerfilUsuario getPerfilusuario() {
		return perfilusuario;
	}

	public void setPerfilusuario(PerfilUsuario perfilusuario) {
		this.perfilusuario = perfilusuario;
	}

	



 
}
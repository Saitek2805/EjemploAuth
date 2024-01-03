package com.example.demo.repositorio;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entidad.PerfilUsuario;

interface PerfilUsuarioRepository extends JpaRepository<PerfilUsuario,Long>{

}

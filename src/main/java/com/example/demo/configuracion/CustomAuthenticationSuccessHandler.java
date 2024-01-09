package com.example.demo.configuracion;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.example.demo.entidad.enumerado.RolUsuario;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    	
    	String targetUrl = determineTargetUrl(authentication);
    	 logger.info("# onAuthenticationSuccess targetUrl: {}#", targetUrl);
    	
    	if (authentication.getPrincipal() instanceof OAuth2User) {
    		OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
		    // Extrae la información necesaria del objeto OAuth2User
		    Map<String, Object> attributes = oAuth2User.getAttributes();
		    String email = (String) attributes.get("email");
		    String name = (String) attributes.get("name");

		    
		    logger.info("# onAuthenticationSuccess email: {}#", email);
    	}
    	
    	
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(Authentication authentication) {
    	 logger.info("# determineTargetUrl #");


        boolean isGoogle = authentication.getPrincipal() instanceof OAuth2User;
        boolean isAdmin = authentication.getAuthorities().contains(new SimpleGrantedAuthority(RolUsuario.ROLE_ADMIN.toString()));
        boolean isUser = authentication.getAuthorities().contains(new SimpleGrantedAuthority(RolUsuario.ROLE_USER.toString()));

        
        if (isAdmin) {
            return "/admin/home"; // URL para administradores
        } else if (isUser) {
            return "/user/home"; // URL para usuarios
        } else if(isGoogle) {
        	 return "/oauth";
        } else {
            throw new IllegalStateException();
        }
    	 
    }
}
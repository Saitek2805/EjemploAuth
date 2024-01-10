package com.example.demo.configuracion;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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
        	
        	//mostrarJWT(authentication);
           
        	 return "/oauth"; // URL para usuarios GOOGLE
        } else {
            throw new IllegalStateException();
        }
    	 
    }

	private void mostrarJWT(Authentication authentication) {
		 OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
    	 // Obtener el token de acceso
        String accessToken = null;
        if (oauthToken.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();
            accessToken = oidcUser.getIdToken().getTokenValue();
        }
        logger.info("#> accessToken # {}" , accessToken);
		
	}
}
package com.athene.portal.components.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.GenericFilterBean;

/**
 *
 * @author E43066
 */
public class PortalAuthFilter extends GenericFilterBean {
//    private ConfigurableJWTProcessor customerJWTProcessor;
    Logger logger = Logger.getLogger(PortalAuthFilter.class.getName());
    
    @Override
    public void doFilter(ServletRequest sr, ServletResponse sr1, FilterChain fc) throws IOException, ServletException {
	HttpServletRequest req = (HttpServletRequest) sr;
	
	List<GrantedAuthority> roles = new ArrayList<>();
	//roles.add(new SimpleGrantedAuthority("ROLE_customer"));
	roles.add(new SimpleGrantedAuthority("ROLE_customer"));
	
	User userT = new User("AWankhede@athene.com", "", roles);
	SecurityContextHolder.getContext().setAuthentication(new AbstractAuthenticationTokenImpl(roles, userT));
	
	Authentication authentication = SecurityContextHolder
		.getContext()
		.getAuthentication();
	if (authentication != null) {
	    Object principalTemp = authentication.getPrincipal();
	    logger.info("Authentication object: " + principalTemp);

	    if (principalTemp != null) {
		User user = (User)principalTemp;
		logger.info("Current user is: " + user.getUsername());
	    }

	    fc.doFilter(sr, sr1);
	    return;
	}
	/*
	Enumeration<String> headerNames = req.getHeaderNames();
	while(headerNames.hasMoreElements()) {
	String header = headerNames.nextElement();
	System.out.println("DEBUG: Header: " + header + ": " + req.getHeader(header));
	}
	*/
	logger.info("No authentication object found");
	Cookie[] cookies = req.getCookies();
	
	String idToken = null;
	String userPool = null;
	
	if (cookies != null && cookies.length > 0) {
	    for (Cookie c: cookies) {
		switch(c.getName()) {
		    case "id_token":
			idToken = c.getValue();
			break;
		    case "user_pool":
			userPool = c.getValue();
			break;
		}
	    }
	}
	
	if (idToken != null) {
	    try {
		//processAuthentication(idToken, userPool);
	    } catch (Exception ex) {
		ex.printStackTrace();
	    }
	}
	
	fc.doFilter(sr, sr1);
    }
    
/*    private void processAuthentication(String idToken, String userPool) throws Exception {
	JWSObject idObj = JWSObject.parse(idToken);
	System.out.println(idObj.getPayload().toString());
	JWTClaimsSet claimSet = customerJWTProcessor.process(idToken, null);
	System.out.println(claimSet.getClaims());
	
	String userName = claimSet.getClaim("email").toString();
	System.out.println("Email set as userName " + userName);
	List<GrantedAuthority> roles = new ArrayList<>();
	//roles.add(new SimpleGrantedAuthority("ROLE_customer"));
	
	String role = claimSet.getClaim("custom:user_pool").toString();
	roles.add(new SimpleGrantedAuthority("ROLE_"+role));
	
	User user = new HippoUser(userName, "", roles, new HashMap<>());
	
	SecurityContextHolder.getContext().setAuthentication(new AbstractAuthenticationTokenImpl(roles, user));
    }*/
    
    private static class AbstractAuthenticationTokenImpl extends AbstractAuthenticationToken {
	
	private final User user;
	
	public AbstractAuthenticationTokenImpl(Collection<? extends GrantedAuthority> authorities, User user) {
	    super(authorities);
	    this.user = user;
	}
	
	@Override
	public Object getCredentials() {
	    return null;
	}
	
	@Override
	public Object getPrincipal() {
	    return user;
	}
    }
    
}

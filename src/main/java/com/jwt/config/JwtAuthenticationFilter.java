package com.jwt.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;

@Configuration
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter{


	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String requestToken = request.getHeader("Authorization");
		
		String username = null;
		String token = null;
		
		if(requestToken != null && requestToken.startsWith("Bearer ")) {
			token = requestToken.substring(7);
			try{
				username=this.jwtUtil.getUsernameFromTokent(token);
			}catch(IllegalArgumentException e){
				System.out.println("Unable to get Token");
				
			}catch(ExpiredJwtException e){
				System.out.println("Unable to get Token");
		
			}catch(MalformedJwtException e){
				System.out.println("Unable to get Token");				
			}

		}else {
			System.out.println("Does not start with Bearer");
		}
		
		if(username != null && SecurityContextHolder.getContext().getAuthentication()==null) {
			
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			
			if(this.jwtUtil.validateToken(token,userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
//			boolean isValid = jwtUtil.validateToken(token, userDetails); //here username comes from database
//			
//			if(isValid) {
//				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
//				
//				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//				
//				//final object stored in Security Context with User Details(username, password)
//				SecurityContextHolder.getContext().setAuthentication(authToken);
//			}
			else {
				System.out.println("invalid token");
			}
			
		}else {
			System.out.println("username is null or context is not null");
		}

		filterChain.doFilter(request, response);
		
	}

}

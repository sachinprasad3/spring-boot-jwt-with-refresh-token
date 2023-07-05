package com.jwt.controller;

import java.util.HashMap;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.dto.UserRequest;
import com.jwt.dto.UserResponse;
import com.jwt.model.Users;
import com.jwt.service.UsresService;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;


@RestController
@RequestMapping("/api/v3/jwt/user")
public class AuthController {
	
	@Autowired
	private UsresService usresService;
	
	@Autowired
	private com.jwt.config.JwtUtil jwtUtil;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private com.jwt.config.UserDetailsServiceImpl userDetailsService;
	
	@PostMapping("/signup")
	public ResponseEntity<?> create(@RequestBody Users user){
		Users usr = usresService.create(user);
		return new ResponseEntity<>(user, HttpStatus.CREATED);
		
	}
	
	
	//2. Validate user and generate token(login)
	@PostMapping(path = "/login")
	public ResponseEntity<UserResponse> loginUser(@RequestBody UserRequest request){
		
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
		UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
		//generating token
		String token = jwtUtil.generateToken(userDetails);
		String refreshToken = jwtUtil.generateToken(userDetails);
		return new ResponseEntity<UserResponse>(new UserResponse(token, refreshToken, "Success! Generated by Silent"), HttpStatus.OK);
	}
	
	
	@PostMapping(path = "/refresh-token")
	public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response){
		
		String requestToken = request.getHeader(HttpHeaders.AUTHORIZATION);
		
		String username = null;
		String refreshToken = null;
		
		if(requestToken != null && requestToken.startsWith("Bearer ")) {
			refreshToken = requestToken.substring(7);
			try{
				username=this.jwtUtil.getUsernameFromTokent(refreshToken);
			}catch(IllegalArgumentException e){
				System.out.println("Unable to get Token");
				
			}catch(ExpiredJwtException e){
				System.out.println("Unable to get Token");
		
			}catch(MalformedJwtException e){
				System.out.println("Unable to get Token");				
			}

		}else {
			System.out.println("Does not start with Bearer");
			return new ResponseEntity<>("Error 1", HttpStatus.FORBIDDEN);
		}
		
		if(username != null) { //NOTE : No Need to re-authenticate user here
			
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			
			if(this.jwtUtil.validateToken(refreshToken,userDetails)) {
				String accessToken = jwtUtil.generateToken(userDetails);
				
				UserResponse userResponse = new UserResponse(accessToken, refreshToken, "Success! Generated by Silent");
				return new ResponseEntity<UserResponse>(userResponse, HttpStatus.CREATED);
			}

			else {
				System.out.println("invalid token");
				return new ResponseEntity<>("Error 2", HttpStatus.FORBIDDEN);
			}
			
		}else {
			System.out.println("username is null or context is not null");
			return new ResponseEntity<>("Error 3", HttpStatus.FORBIDDEN);
		}

	}
	
	
	
	@GetMapping("/welcome")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<Map<String, String>> welcome(){
		Map<String, String> map = new HashMap<>();
		map.put("msg", "GOTCHA");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	
}

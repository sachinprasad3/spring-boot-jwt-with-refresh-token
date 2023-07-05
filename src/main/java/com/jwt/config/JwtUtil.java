package com.jwt.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {
	//public static final Long JWT_TOKEN_VALIDITY= 2592000000L;
	 
	public static final Long JWT_TOKEN_VALIDITY= 604800L; //7 Days 604800L
	
	public static final Long JWT_REFRESH_TOKEN_VALIDITY= 1296000L;
	 private String secret = "jwtTokenKey";
 
	 
	 //token generation
//	 public String generateToken(UserDetails userDetails) {
//		 Map<String,Object> claims=new HashMap<String, Object>();
//		 //claims.put("role", userDetails.getAuthorities());
//		 return doGenerateToken(claims, userDetails.getUsername());
//	 }
	 
	 public String generateToken(UserDetails userDetails) {
		 Map<String,Object> claims=new HashMap<String, Object>();
		 //claims.put("username", userDetails.getUsername());
		 return doGenerateToken(claims, userDetails.getUsername());
	 }
	 
	 public String doGenerateToken(Map<String,Object> claims,String subject) {
		 return Jwts.builder()
				 .setClaims(claims)
				 .setSubject(subject)
				 .setIssuedAt(new Date())
				 .setExpiration(new Date(System.currentTimeMillis()+JWT_TOKEN_VALIDITY))
				 .signWith(SignatureAlgorithm.HS512, secret)
				 .compact();
	 }
	 //end of Token genetation
	 
	 
	 //Generate Refresh Token
	 public String generateRefreshToken(UserDetails userDetails) {
		 Map<String,Object> claims=new HashMap<String, Object>();

		 return Jwts.builder()
				 .setClaims(claims)
				 .setSubject(userDetails.getUsername())
				 .setIssuedAt(new Date())
				 .setExpiration(new Date(System.currentTimeMillis()+JWT_REFRESH_TOKEN_VALIDITY))
				 .signWith(SignatureAlgorithm.HS512, secret)
				 .compact();
		 
	 }
	 
	 
	 //fetch token's username
	 public String getUsernameFromTokent(String token) {
		 return getClaimFromToken(token,Claims::getSubject);
	 }
	 
	 //fetch token's expiration
	 public Date getExpirationDateFromToken(String token) {
		 Date d=getClaimFromToken(token,Claims::getExpiration);
		 return d;
		 
	 }
	 
 
	 //validation
	 public <T>T getClaimFromToken(String token,Function<Claims, T> claimsResolver){
		 final Claims claims= getAllClaimsFromToken(token);
		 return claimsResolver.apply(claims);
	 }

	private Claims getAllClaimsFromToken(String token) {
		
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}
	
	 private Boolean isTokenExpired(String token) {
		 final Date expiration = getExpirationDateFromToken(token);
		 Date curr = new Date();
		 Boolean expi=expiration.before(curr);
		 return expi;
	 }
	
	 
	 public Boolean validateToken(String token,UserDetails userDetails) {
		 final String username = getUsernameFromTokent(token);
		 return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	 }
	
}

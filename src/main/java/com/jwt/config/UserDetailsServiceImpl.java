package com.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.jwt.model.Users;
import com.jwt.service.UsresService;



@Service
public class UserDetailsServiceImpl  implements UserDetailsService{

	@Autowired
	private UsresService userService;
	
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//System.out.println("here");
		Users user = this.userService.getUserByUsername(username);
		
		if(user==null) {
			throw new UsernameNotFoundException("Username not found");
		}
		//user.setRoles(userService.getRolesOfUser(user.getUser()));
	
			return new CustomUserDetail(user);

	}

}
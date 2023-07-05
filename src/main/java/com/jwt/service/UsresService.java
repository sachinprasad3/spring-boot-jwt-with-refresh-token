package com.jwt.service;

import com.jwt.model.Users;

public interface UsresService {
	
	public Users create(Users user);

	public Users getUserByUsername(String username);
}

package com.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.jwt.model.Users;
import com.jwt.repository.UsersRepository;

@Service
public class UsresServiceImpl implements UsresService{
	
	@Autowired
	private UsersRepository userRepo;
	
	@Override
	public Users create(Users user) {
		return userRepo.save(user);
	}

	@Override
	public Users getUserByUsername(String username) {
		// TODO Auto-generated method stub
		return userRepo.getUserByUsername(username);
	}

}

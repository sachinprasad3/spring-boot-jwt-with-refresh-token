package com.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.jwt.model.Users;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long>{

	@Query("from Users u where u.username=:username")
	public Users getUserByUsername(String username);

}

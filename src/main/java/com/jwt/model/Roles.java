package com.jwt.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import lombok.Data;

@Entity
@Data
public class Roles {
	
	@Id
	@GeneratedValue
	private long id;
	private String role;
}

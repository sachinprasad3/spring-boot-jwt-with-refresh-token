package com.jwt.dto;

import lombok.Data;

@Data
public class UserResponse {
	
	private String accessToken;
	private String refreshToken;
	private String message;
	
	
	public UserResponse() {
	}
	
	public UserResponse(String accessToken, String refreshToken, String message) {
		super();
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.message = message;
	}

}

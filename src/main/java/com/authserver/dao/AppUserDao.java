package com.authserver.dao;

import com.authserver.model.AppUserDetails;

public interface AppUserDao {
	
	AppUserDetails findByUsername(String username);

}

package com.authserver.dao.impl;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.authserver.dao.AppUserDao;
import com.authserver.model.AppUserDetails;
import com.authserver.repositories.AppUserRepo;

@Service
public class AppUserDaoImpl implements AppUserDao {
	
	private AppUserRepo appUserRepo;
	
	

	public AppUserDaoImpl(AppUserRepo appUserRepo) {
		super();
		this.appUserRepo = appUserRepo;
	}



	@Override
	public AppUserDetails findByUsername(String username) {
		Optional<AppUserDetails> userRoleDetailsOpt = appUserRepo.findByUsername(username);
		return userRoleDetailsOpt.orElse(new AppUserDetails());
	}

}

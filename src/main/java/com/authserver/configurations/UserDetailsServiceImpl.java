package com.authserver.configurations;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.authserver.dao.AppUserDao;
import com.authserver.model.AppUserDetails;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
	private static final Logger LOGGER = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

	private AppUserDao appUserDao;
	
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	public UserDetailsServiceImpl(AppUserDao appUserDao, BCryptPasswordEncoder passwordEncoder) {
		super();
		this.appUserDao = appUserDao;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUserDetails appUserDetails = appUserDao.findByUsername(username);

		if (appUserDetails == null)
			throw new UsernameNotFoundException("user not found");

		Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

		appUserDetails.getRoles().forEach(role -> grantedAuthorities.add(new SimpleGrantedAuthority(role)));

		LOGGER.info("appUserDetails: {}", appUserDetails);
		return new User(appUserDetails.getUsername(), appUserDetails.getPwd(), grantedAuthorities);
	}

}

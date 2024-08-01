package com.authserver.repositories;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.authserver.model.AppUserDetails;

@Repository
public interface AppUserRepo extends MongoRepository<AppUserDetails, String> {
	
	Optional<AppUserDetails> findByUsername(String username);

}

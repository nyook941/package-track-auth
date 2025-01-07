package com.kennan.PackageTrackAuth.repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.kennan.PackageTrackAuth.models.User;

@Repository
public interface UserRepository extends MongoRepository<User, String> {}
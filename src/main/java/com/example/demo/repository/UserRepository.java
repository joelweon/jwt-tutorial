package com.example.demo.repository;

import com.example.demo.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
  @EntityGraph(attributePaths = "authorities") // EntityGraph -> Eager조회로 authentity 가져옴
  Optional<User> findOneWithAuthoritiesByUsername(String username);
}

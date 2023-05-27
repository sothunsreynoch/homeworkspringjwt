package com.example.springjwt.service;

import com.example.springjwt.model.Users;
import com.example.springjwt.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users user = (Users) userRepository.getAllUser(username);
        return User.builder()
                .username(user.getUsername())
                .password(user.getSecret_key())
                .roles("USER")
                .build();
    }
}

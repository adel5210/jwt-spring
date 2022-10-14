package com.adel.jwtspring.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    private static final Map<String,String> dummyDbUsers = new HashMap<>();

    static {
        //https://www.javainuse.com/onlineBcrypt
        dummyDbUsers.put("adel", "$2a$10$8Uv1BuUJeUnCQ.qWCiFT6.IYkjz5VePjKwcMS92LfY7L.8UFN6LBK"); //password
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(!dummyDbUsers.containsKey(username)){
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        return new User(username, dummyDbUsers.get(username), new ArrayList<>());
    }
}

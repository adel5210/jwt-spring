package com.adel.jwtspring.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
@NoArgsConstructor
@AllArgsConstructor
@Data
public class JwtRequest implements Serializable {

    private static final long serialVersionUID = -2215306320336588082L;

    private String username;
    private String password;

}

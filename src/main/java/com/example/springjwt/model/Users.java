package com.example.springjwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Users {
    private int id;
    private String username;
    private String gender;
    private String address;
    private String email;
    private String secret_key;


}

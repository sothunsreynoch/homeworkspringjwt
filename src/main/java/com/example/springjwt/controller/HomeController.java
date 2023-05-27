package com.example.springjwt.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
//@Slf4j
public class HomeController {
    Logger logger = LoggerFactory.getLogger(HomeController.class);
    @GetMapping("/home")
    public String homepage(Authentication authentication){
        var user = authentication.getPrincipal();
       logger.info("Users is : {}",authentication.getPrincipal());
       logger.info("Users is : {}",authentication.getCredentials());
       logger.info("USer is :{}",authentication.getDetails());
       logger.info("Users is : {}",authentication.getAuthorities());
        return "Hello "+authentication.getName();
    }


}

package org.springframework.samples.petclinic.user;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.samples.petclinic.user.UserDTO;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
public class UserController {

    @PostMapping("/user")
    public UserDTO login(@RequestParam("user") String username,
                         @RequestParam("password") String pwd) {

        // validar con la BD
        // bcrypt
        String token = getJWTToken(username);
        UserDTO user = new UserDTO();
        user.setUser(username);
        user.setToken(token);
        return user;

    }


    @PostMapping("/user/JSON")
    public UserDTO login(@RequestBody UserDTO userDTO) {
        // vaidacion con la BD
        String token = getJWTToken(userDTO.getUser());

        userDTO.setToken(token);
        return userDTO;

    }

    private String getJWTToken(String username) {
        String secretKey = "secreto";
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils
            .commaSeparatedStringToAuthorityList("ROLE_USER");

        String token = Jwts
            .builder()
            .setId("petJWT")
            .setSubject(username)
            .claim("authorities",
                grantedAuthorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()))
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + 6000000))
            .signWith(SignatureAlgorithm.HS512,
                secretKey.getBytes()).compact();

        return "Bearer " + token;
    }
}

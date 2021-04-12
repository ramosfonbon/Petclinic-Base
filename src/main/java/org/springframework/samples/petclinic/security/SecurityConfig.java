package org.springframework.samples.petclinic.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.samples.petclinic.security.JWTAuthorizationFilter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Order(1)
    @Configuration
    public static class RestConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .antMatcher("/API/**")
                .cors()
                    .and()
                .csrf()
                    .disable() // we don't need CSRF because our token is invulnerable
                .authorizeRequests()
                    .antMatchers(HttpMethod.POST, "user").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .addFilterAfter(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                    // this disables session creation on Spring Security
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }

    }


    @Order(2)
    @Configuration
    public static class WebConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.exceptionHandling().accessDeniedPage("/403");

            http

                    .formLogin()
                    .and()
                    .authorizeRequests().antMatchers("/owners/**").authenticated()
                    .antMatchers("/user").permitAll();

        }


        @Override
        public void configure(WebSecurity web) throws Exception {
            web
                    .ignoring()

                        .antMatchers(
                                HttpMethod.GET,
                                "/",
                                "/*.html",
                                "/**/favicon.ico",
                                "/**/*.html",
                                "/**/*.css",
                                "/**/*.js"

                        )
                        .antMatchers(
                                HttpMethod.POST,
                                "/user",
                                "/owners/**"
                        )
                ;
            ;
        }
    }
}

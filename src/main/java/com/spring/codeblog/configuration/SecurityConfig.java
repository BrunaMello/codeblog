package com.spring.codeblog.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //criptografando a senha
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //uris que podem ser acessadas sem autenticacao
    private static final String[] AUTH_LIST = {
            "/",
            "/posts",
            "/posts/{id}",
    };

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http.csrf().disable().authorizeRequests()
                //colocar as uril que nao precisam de autenticacao
                .antMatchers(AUTH_LIST).permitAll()
                //todas as outras uri que precisam de autenticacao
                .anyRequest().authenticated()
                //acessar a pagina de login tb precisa de autenticacao
                .and().formLogin().permitAll()
                //fazer logout
                .and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication()
                //credenciais para fazer o login pass é somente 123
                .withUser("bruna").password(passwordEncoder().encode("123")).roles("ADMIN");
    }

    @Override
    public void configure(WebSecurity web) throws Exception{
        //ignorar os pastas estaticas para serem exibidas
        web.ignoring().antMatchers("/bootstrap/**");
       // web.ignoring().antMatchers("bootstrap/**", "style/**");
    }
}

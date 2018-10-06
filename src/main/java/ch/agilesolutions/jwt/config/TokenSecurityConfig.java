package ch.agilesolutions.jwt.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import ch.agilesolutions.jwt.security.JwtAuthenticationFilter;

@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 9)
public class TokenSecurityConfig extends WebSecurityConfigurerAdapter {

       @Override
       protected void configure(HttpSecurity http) throws Exception {

             http.antMatcher("/api/**").httpBasic()
                    .and()
                    .addFilterBefore(new JwtAuthenticationFilter(),
                                 WebAsyncManagerIntegrationFilter.class)
                    .authorizeRequests()
                    .antMatchers("/api/**").authenticated();

       }

 

       @Override
       public void configure(WebSecurity web) throws Exception {

             super.configure(web);

       }
}

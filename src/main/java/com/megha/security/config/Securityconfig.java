package com.megha.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class Securityconfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private BCryptPasswordEncoder encode;
	
	//Authentication
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth.inMemoryAuthentication().withUser("sam").password("{noop}abc").authorities("ADMIN");
		auth.inMemoryAuthentication().withUser("ram").password("{noop}def").authorities("EMPLOYEE");
		auth.inMemoryAuthentication().withUser("megha").password("{noop}ghi").authorities("USER");
		
	}
	//Authorization
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
		.antMatchers("/home").permitAll()
		.antMatchers("/welcome").authenticated()
		.antMatchers(HttpMethod.POST,"/register").permitAll()//we can give along with httpMethod also.
		.antMatchers("/get").authenticated()
		.antMatchers("/block").hasAuthority("ADMIN")
		.antMatchers("/common").hasAnyAuthority("EMPLOYEE","USER")
		.anyRequest().hasAnyAuthority("EMPLOYEE","ADMIN","USER")
		
		//login form details
		.and()
		.formLogin()
		.defaultSuccessUrl("/welcome",true)
		
		//logout details
		.and()
		.logout()
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		
		//Exception details
		
		.and()
		.exceptionHandling()
		.accessDeniedPage("/denied");
		
	}
}

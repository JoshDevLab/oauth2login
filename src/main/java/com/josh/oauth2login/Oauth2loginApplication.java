package com.josh.oauth2login;

import com.josh.oauth2login.config.properties.AppProperties;
import com.josh.oauth2login.config.properties.CorsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
		CorsProperties.class,
		AppProperties.class
})
public class Oauth2loginApplication {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2loginApplication.class, args);
	}

}

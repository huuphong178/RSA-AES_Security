package com.vng.hotelrest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;

@SpringBootApplication
@EnableJpaAuditing
//@EnableJdbcHttpSession
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

}

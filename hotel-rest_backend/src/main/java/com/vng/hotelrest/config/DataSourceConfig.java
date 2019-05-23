package com.vng.hotelrest.config;

import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;

import javax.sql.DataSource;

public class DataSourceConfig {
    @Bean
    public DataSource dataSource() {
        DataSourceBuilder dataSourceBuilder = DataSourceBuilder.create();
        dataSourceBuilder.url("jdbc:mysql://localhost:3306/hotel?useUnicode=true&characterEncoding=UTF-8");
        dataSourceBuilder.driverClassName("com.mysql.jdbc.Driver");
        dataSourceBuilder.username("root");
        dataSourceBuilder.password("123456");
        return dataSourceBuilder.build();
    }
}

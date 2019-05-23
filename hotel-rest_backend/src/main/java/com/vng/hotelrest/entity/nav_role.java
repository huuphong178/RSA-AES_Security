package com.vng.hotelrest.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "nav_role")
@EntityListeners(AuditingEntityListener.class)
public class nav_role implements Serializable {
    @Id
    @Column(name="name")
    private String name;
    @Column(name = "roles")
    private String roles;

    public nav_role() {
    }

    public nav_role(String name, String roles) {
        this.name = name;
        this.roles = roles;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }
}

package com.example.springsecurity.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.example.parrotsysmap.security.ApplicationUserPermission.COURSE_READ;
import static com.example.parrotsysmap.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.parrotsysmap.security.ApplicationUserPermission.STUDENT_READ;
import static com.example.parrotsysmap.security.ApplicationUserPermission.STUDENT_WRITE;

public enum ApplicationUserRole {
    ADMIN(Sets.newHashSet(STUDENT_WRITE, STUDENT_READ, COURSE_READ, COURSE_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(STUDENT_READ, COURSE_READ)),

    STUDENT(Sets.newHashSet());


    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}

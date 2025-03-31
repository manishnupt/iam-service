package com.hrms.iam_service.dto;

import lombok.Data;

@Data
public class RealmRoleDetails {
    private String id;
    private String name;
    private boolean composite;
    private String containerId;
    private String description;
}

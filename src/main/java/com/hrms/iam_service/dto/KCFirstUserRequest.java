package com.hrms.iam_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KCFirstUserRequest {

    private String userName;
    private String email;
    private String password;
    private String realmName;
    private boolean temporaryPassword;
}

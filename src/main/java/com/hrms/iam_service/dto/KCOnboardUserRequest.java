package com.hrms.iam_service.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class KCOnboardUserRequest {

    @NotEmpty
    private String username;

    @NotEmpty
    private String email;
    private boolean enabled;
    private List<Credential> credentials;

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Credential {
        private String type;
        private String value;
        private boolean temporary;
    }

}

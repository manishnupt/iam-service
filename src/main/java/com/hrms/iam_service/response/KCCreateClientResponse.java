package com.hrms.iam_service.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class KCCreateClientResponse {
    private String id;
    private String clientId;
    private String name;
    private String clientSecret;
    private String realmName;
}

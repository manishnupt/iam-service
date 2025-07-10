package com.hrms.iam_service.utility;

import java.util.Arrays;
import java.util.List;

public class Constants {

    public static final int INTERNAL_SERVER_ERROR_CODE = 500;

    public static final int RESOURCE_CREATED_CODE = 201;

    public static final int RESOURCE_OK_CODE = 200;

    public static final int RESOURCE_NOT_FOUND_CODE = 404;

    public static final int UNAUTHORIZED_ACCESS_CODE = 401;

    public static final int BAD_REQUEST_CODE = 400;

    public static final int NO_CONTENT_CODE = 204;

    public static final String GRANT_TYPE_PASSWORD = "password";

    public static final String CLIENT_ID_ADMIN_CLI = "admin-cli";

    public static final String CLIENT_ID_ADMIN_USERNAME = "admin";

    public static final String CLIENT_ID_ADMIN_PASSWORD = "admin@123";

    public static final String TENANT_REDIRECT_URI = "%srealms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid";

    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";

    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    public static final String TENANT_CLIENT_ID = "hrms-client";

    public static final String DEFAULT_KEYCLOAK_CLIENT = "hrms-client";

    public static final String DEFAULT_KEYCLOAK_PROTOCOL = "openid-connect";

    public static final String TOKEN_TYPE_ACCESS_TOKEN = "access_token";

    public static final String TOKEN_TYPE_REFRESH_TOKEN = "refresh_token";

    public static final String EXTRACT_USER_ID_REGEX = ".*/users/([a-f0-9\\-]+)$";
    public static final String EXTRACT_GROUP_ID_REGEX = ".*/groups/([a-f0-9\\-]+)$";


    public static final List<String> roles = Arrays.asList(
            "EMPLOYEE_MGMT",
            "HIRING_MGMT",
            "ASSET_MANAGEMENT",
            "EMPLOYEE_ADD",
            "EMPLOYEE_EDIT",
            "DEACTIVATE_EMPLOYEE",
            "TIMESHEET_ACCESS",
            "LEAVE_MGMT_ACCESS",
            "ASSET_REGISTRATION",
            "ASSET_ALLOCATION"
    );

}

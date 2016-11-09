/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.cas.saml.response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.response.CASLoginResponse;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class HttpCASSAMLResponseFactory extends HttpIdentityResponseFactory {

    private static Log log = LogFactory.getLog(HttpCASSAMLResponseFactory.class);

    @Override
    public String getName() {
        return "HttpCASSAMLResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if (identityResponse instanceof CASServiceValidateSAMLResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        if (identityResponse instanceof CASLoginResponse) {
            return sendResponse(identityResponse);
        } else {
            return sendServiceValidationResponse(identityResponse);
        }
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(HttpIdentityResponse.HttpIdentityResponseBuilder
                                                                           httpIdentityResponseBuilder, IdentityResponse
                                                                           identityResponse) {
        return create(identityResponse);
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder sendResponse(IdentityResponse identityResponse) {
        CASLoginResponse loginResponse = ((CASLoginResponse) identityResponse);
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        Cookie cookie = loginResponse.getCasCookie();
        String serviceTicketId = loginResponse.getServiceTicketId();
        String redirectUrl = loginResponse.getRedirectUrl();
        Map<String, String[]> queryParams = new HashMap();
        queryParams.put(CASSSOConstants.SERVICE_TICKET_ARGUMENT, new String[]{serviceTicketId});
        builder.addCookie(cookie);
        builder.setParameters(queryParams);
        builder.setRedirectURL(redirectUrl);
        builder.setStatusCode(HttpServletResponse.SC_MOVED_TEMPORARILY);
        return builder;
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder sendServiceValidationResponse(IdentityResponse identityResponse) {
        CASServiceValidateSAMLResponse casServiceValidationSAMLResponse = ((CASServiceValidateSAMLResponse)
                identityResponse);
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        String responseString = casServiceValidationSAMLResponse.getResponseString();
        String redirectUrl = casServiceValidationSAMLResponse.getRedirectUrl();
        builder.setBody(responseString);
        builder.setStatusCode(HttpServletResponse.SC_OK);
        builder.setRedirectURL(redirectUrl);
        return builder;
    }
}

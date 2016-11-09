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

package org.wso2.carbon.identity.sso.cas.saml.request;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.request.CASIdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Locale;

public class CASServiceValidateSAMLRequest extends CASIdentityRequest {
    private static Log log = LogFactory.getLog(CASServiceValidateSAMLRequest.class);
    Locale locale;

    public String getSamlRequest() {
        return samlRequest;
    }

    String samlRequest;

    public CASServiceValidateSAMLRequest(IdentityRequest.IdentityRequestBuilder builder) {
        super((CASIdentityRequestBuilder) builder);
        this.locale = ((CASServiceValidateSAMLRequestBuilder) builder).locale;
        this.samlRequest = ((CASServiceValidateSAMLRequestBuilder) builder).samlRequest;
    }

    public String getServiceRequest() {
        return CASSSOConstants.SERVICE_PROVIDER_ARGUMENT;
    }

    public String getServiceTicket() {
        return CASSSOConstants.SERVICE_TICKET_ARGUMENT;
    }

    public Locale getLocale() {
        return this.locale;
    }

    public static class CASServiceValidateSAMLRequestBuilder extends CASIdentityRequestBuilder {

        Locale locale;
        String samlRequest;

        public CASServiceValidateSAMLRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
            this.setSAMLRequest(request);
        }

        public CASServiceValidateSAMLRequestBuilder() {
        }

        @Override
        public CASServiceValidateSAMLRequest build() {
            return new CASServiceValidateSAMLRequest(this);
        }

        public CASServiceValidateSAMLRequestBuilder setLocale(HttpServletRequest request) {
            this.locale = request.getLocale();
            return this;
        }

        private void setSAMLRequest(HttpServletRequest req) {
            try {
                // Read from request
                StringBuilder buffer = new StringBuilder();
                BufferedReader reader = req.getReader();
                String line;
                while ((line = reader.readLine()) != null) {
                    buffer.append(line);
                }
                this.samlRequest = buffer.toString();
            } catch (IOException ioex) {
                log.debug("Error while getting samlRequest from http request");
            }
        }

    }
}



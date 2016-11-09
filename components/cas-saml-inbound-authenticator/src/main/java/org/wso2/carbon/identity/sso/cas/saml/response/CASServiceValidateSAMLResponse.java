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
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.response.CASResponse;
import org.wso2.carbon.identity.sso.cas.saml.SAMLValidationHandler;
import org.wso2.carbon.identity.sso.cas.saml.request.CASServiceValidateSAMLRequest;

public class CASServiceValidateSAMLResponse extends CASResponse {

    private String responseXml;
    private String redirectUrl;

    protected CASServiceValidateSAMLResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);
        this.responseXml = ((CASServiceValidationSAMLResponseBuilder) builder).responseXml;
        this.redirectUrl = ((CASServiceValidationSAMLResponseBuilder) builder).redirectUrl;
    }

    public String getResponseString() {
        return responseXml;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public CASMessageContext getContext() {
        return (CASMessageContext) this.context;
    }

    public static class CASServiceValidationSAMLResponseBuilder extends CASResponseBuilder {
        private static Log log = LogFactory.getLog(CASServiceValidationSAMLResponseBuilder.class);
        private String responseXml;
        private String redirectUrl;

        public CASServiceValidationSAMLResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public CASServiceValidateSAMLResponse build() {
            return new CASServiceValidateSAMLResponse(this);
        }

        public CASServiceValidationSAMLResponseBuilder setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }

        public String buildResponse() {
            SAMLValidationHandler samlValidationHandler = new SAMLValidationHandler();
            responseXml = samlValidationHandler.buildResponse((CASServiceValidateSAMLRequest) this.context.getRequest());
            return responseXml;
        }
    }
}


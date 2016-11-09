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
package org.wso2.carbon.identity.sso.cas.saml.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.sso.cas.processor.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.cas.saml.processor.CASSAMLServiceValidationProcessor;
import org.wso2.carbon.identity.sso.cas.saml.request.CASSAMLIdentityRequestFactory;
import org.wso2.carbon.identity.sso.cas.saml.response.HttpCASSAMLResponseFactory;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;


/**
 * @scr.component name="identity.sso.cas.saml.component" immediate="true"
 */

public class CASSAMLAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(CASSAMLAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {

        CASSSOUtil.setBundleContext(ctxt.getBundleContext());

        ctxt.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(), new
                CASSAMLIdentityRequestFactory(), null);
        ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(), new
                HttpCASSAMLResponseFactory(), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new SPInitSSOAuthnRequestProcessor
                (), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new CASSAMLServiceValidationProcessor(), null);
        log.info("Identity CAS SSO bundle is activated");
    }

}

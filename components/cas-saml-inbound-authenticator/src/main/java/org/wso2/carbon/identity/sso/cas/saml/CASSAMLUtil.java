package org.wso2.carbon.identity.sso.cas.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfiguration;
import org.wso2.carbon.identity.sso.cas.util.CASResourceReader;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.text.SimpleDateFormat;
import java.util.Date;

public class CASSAMLUtil {
	private static String soapEnvelope;
	private static String successResponse;
	private static String failureResponse;
	private static String samlAttribute;
	private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

	private static Log log = LogFactory.getLog(CASSAMLUtil.class);


	static {
		try {
			soapEnvelope = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
					"<SOAP-ENV:Header/>\n" +
					"<SOAP-ENV:Body>\n" +
					"<Response xmlns=\"urn:oasis:names:tc:SAML:1.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:1.0:protocol\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" IssueInstant=\"$timestamp\" MajorVersion=\"1\" MinorVersion=\"1\" Recipient=\"$recipient\" ResponseID=\"$responseId\" InResponseTo=\"$inResponseTo\">$samlResponse</Response>\n" +
					"</SOAP-ENV:Body>\n" +
					"</SOAP-ENV:Envelope>\n";

			successResponse = "<Status>\n" +
					"<StatusCode Value=\"samlp:Success\"></StatusCode>\n" +
					"</Status>\n" +
					"<Assertion xmlns=\"urn:oasis:names:tc:SAML:1.0:assertion\" AssertionID=\"$assertionId\" IssueInstant=\"$timestamp\" Issuer=\"$issuer\" MajorVersion=\"1\" MinorVersion=\"1\">\n" +
					"  <Conditions NotBefore=\"$notBefore\" NotOnOrAfter=\"$notAfter\"> \n" +
					"    <AudienceRestrictionCondition>\n" +
					"      <Audience>$audience</Audience>\n" +
					"    </AudienceRestrictionCondition>\n" +
					"  </Conditions>\n" +
					"  <AttributeStatement>\n" +
					"    <Subject>\n" +
					"      <NameIdentifier>$username</NameIdentifier>\n" +
					"      <SubjectConfirmation>\n" +
					"        <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:artifact</ConfirmationMethod>\n" +
					"      </SubjectConfirmation>\n" +
					"    </Subject>\n" +
					"    $attributes\n" +
					"  </AttributeStatement>\n" +
					"  <AuthenticationStatement AuthenticationInstant=\"$timestamp\" AuthenticationMethod=\"urn:oasis:names:tc:SAML:1.0:am:password\">\n" +
					"   <Subject>\n" +
					"      <NameIdentifier>$username</NameIdentifier>\n" +
					"      <SubjectConfirmation>\n" +
					"        <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:artifact</ConfirmationMethod>\n" +
					"      </SubjectConfirmation>\n" +
					"    </Subject>\n" +
					"  </AuthenticationStatement>\n" +
					"</Assertion>\n";

			failureResponse = "<Status>\n" +
					"<StatusCode Value=\"samlp:Responder\"/>\n" +
					"<StatusMessage>\n" +
					"$errorMessage\n" +
					"</StatusMessage>\n" +
					"</Status>\n";

			samlAttribute = "    <Attribute AttributeName=\"$attributeName\" AttributeNamespace=\"http://www.ja-sig.org/products/cas/\">\n" +
					"      <AttributeValue>$attributeValue</AttributeValue>\n" +
					"    </Attribute>\n";

		} catch (Exception ex) {
			log.error("SAML response templates cannot be loaded", ex);
		}
	}

	public static String getSOAPEnvelope() {
		return soapEnvelope;
	}

	public static String getSAMLSuccessResponse(String serviceProviderUrl, String username, String requestId, String attributes) {
		String randomId = UUIDGenerator.generateUUID().replaceAll("-", "");
		Date baseDate = new Date();
		Date dateBefore = new Date();

		dateBefore.setTime(baseDate.getTime() - 1000);
		Date dateAfter = new Date();
		dateAfter.setTime(baseDate.getTime() + 1000);

		String attributeFilteredUrl = serviceProviderUrl.replaceAll("&", "&amp;");

		return soapEnvelope
				.replace("$samlResponse", successResponse)
				.replaceAll("\\$issuer", "localhost")
				.replaceAll("\\$recipient", attributeFilteredUrl)
				.replaceAll("\\$audience", attributeFilteredUrl)
				.replaceAll("\\$timestamp", formatSoapDate(baseDate))
				.replaceAll("\\$notBefore",
						formatSoapDate(dateBefore))
				.replaceAll("\\$notAfter", formatSoapDate(dateAfter))
				.replaceAll("\\$assertionId", "_assertion" + randomId)
				.replaceAll("\\$inResponseTo", "_" + requestId)
				.replaceAll("\\$responseId", "_response" + randomId)
				.replace("$attributes", attributes)
				.replaceAll("\\$username", username);
	}

	public static String getSAMLFailureResponse(String serviceProviderUrl, String requestId, String errorMessage) {
		Date baseDate = new Date();
		String randomId = "_"
				+ UUIDGenerator.generateUUID().replaceAll("-", "");

		return soapEnvelope
				.replace("$samlResponse", failureResponse)
				.replaceAll("\\$issuer", "localhost")
				.replaceAll("\\$recipient", serviceProviderUrl)
				.replaceAll("\\$errorMessage", errorMessage)
				.replaceAll("\\$responseId", randomId)
				.replaceAll("\\$inResponseTo", "_" + requestId)
				.replaceAll("\\$timestamp", formatSoapDate(baseDate));
	}

	public static String getSAMLAttribute(String key, String value) {
		return samlAttribute
				.replace("$attributeName", key)
				.replace("$attributeValue", value);
	}


	public static String getBaseUrl(String url, boolean returnBaseUrl) {
		int pathSeparatorPosition = url.indexOf(';');

		if( returnBaseUrl && pathSeparatorPosition == -1 ) {
			pathSeparatorPosition = url.indexOf('?');
		}

		if( pathSeparatorPosition != -1 ) {
			return url.substring(0, pathSeparatorPosition);
		} else {
			return url;
		}
	}

	public static String formatSoapDate(Date dateToFormat) {
		return dateFormat.format(dateToFormat);
	}
}
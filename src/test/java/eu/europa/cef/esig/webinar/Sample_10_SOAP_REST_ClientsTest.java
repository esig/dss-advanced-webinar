package eu.europa.cef.esig.webinar;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.cxf.ext.logging.LoggingInInterceptor;
import org.apache.cxf.ext.logging.LoggingOutInterceptor;
import org.apache.cxf.jaxb.JAXBDataBinding;
import org.apache.cxf.jaxrs.client.JAXRSClientFactoryBean;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.DataToSignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.SignOneDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.rest.client.RestDocumentSignatureService;
import eu.europa.esig.dss.ws.signature.soap.client.DateAdapter;
import eu.europa.esig.dss.ws.signature.soap.client.SoapDocumentSignatureService;

public class Sample_10_SOAP_REST_ClientsTest {

    // Postman examples :
    // https://github.com/esig/dss/tree/master/dss-cookbook/src/main/postman

    // SOAP UI examples :
    // https://github.com/esig/dss/tree/master/dss-cookbook/src/main/soapui

    @Test
    void SOAP() throws IOException {

        // CXF configuration with a local bundle

        final JAXBDataBinding dataBinding = new JAXBDataBinding();
        dataBinding.getConfiguredXmlAdapters().add(new DateAdapter());

        final Map<String, Object> props = new HashMap<>();
        props.put("mtom-enabled", Boolean.TRUE);

        final JaxWsProxyFactoryBean factory = new JaxWsProxyFactoryBean();
        factory.setServiceClass(SoapDocumentSignatureService.class);
        factory.setProperties(props);
        factory.setDataBinding(dataBinding);
        factory.setAddress("http://localhost:8080/services/soap/signature/one-document");

        final LoggingInInterceptor loggingInInterceptor = new LoggingInInterceptor();
        factory.getInInterceptors().add(loggingInInterceptor);
        factory.getInFaultInterceptors().add(loggingInInterceptor);

        final LoggingOutInterceptor loggingOutInterceptor = new LoggingOutInterceptor();
        factory.getOutInterceptors().add(loggingOutInterceptor);
        factory.getOutFaultInterceptors().add(loggingOutInterceptor);

        final SoapDocumentSignatureService soapClient = factory.create(SoapDocumentSignatureService.class);

        // Let's start with DSS...

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user.p12"), new PasswordProtection("ks-password".toCharArray()));

        final DSSPrivateKeyEntry dssPrivateKeyEntry = token.getKey("good-user");

        final DataToSignOneDocumentDTO dataToSign = new DataToSignOneDocumentDTO();

        final RemoteSignatureParameters parameters = new RemoteSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        parameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getEncoded()));
        dataToSign.setParameters(parameters);

        final RemoteDocument toSignDocument = new RemoteDocument();
        toSignDocument.setBytes("Hello CEF!".getBytes("UTF-8"));
        dataToSign.setToSignDocument(toSignDocument);

        // get data to sign

        final ToBeSignedDTO toBeSignedDTO = soapClient.getDataToSign(dataToSign);
        assertNotNull(toBeSignedDTO);

        // sign locally
        final SignatureValue signatureValue = token.sign(DTOConverter.toToBeSigned(toBeSignedDTO), parameters.getDigestAlgorithm(), dssPrivateKeyEntry);
        assertNotNull(signatureValue);

        final SignOneDocumentDTO signOneDoc = new SignOneDocumentDTO();
        signOneDoc.setToSignDocument(toSignDocument);
        signOneDoc.setParameters(parameters);
        signOneDoc.setSignatureValue(DTOConverter.toSignatureValueDTO(signatureValue));

        // sign document

        final RemoteDocument signedDocument = soapClient.signDocument(signOneDoc);
        assertNotNull(signedDocument);
        assertNotNull(signedDocument.getBytes());

    }

    @Test
    void REST() throws IOException {

        // CXF configuration with a local bundle

        final JAXRSClientFactoryBean factory = new JAXRSClientFactoryBean();

        factory.setAddress("http://localhost:8080/services/rest/signature/one-document");
        factory.setServiceClass(RestDocumentSignatureService.class);
        factory.setProviders(Arrays.asList(new JacksonJsonProvider()));

        final LoggingInInterceptor loggingInInterceptor = new LoggingInInterceptor();
        factory.getInInterceptors().add(loggingInInterceptor);
        factory.getInFaultInterceptors().add(loggingInInterceptor);

        final LoggingOutInterceptor loggingOutInterceptor = new LoggingOutInterceptor();
        factory.getOutInterceptors().add(loggingOutInterceptor);
        factory.getOutFaultInterceptors().add(loggingOutInterceptor);

        final RestDocumentSignatureService restClient = factory.create(RestDocumentSignatureService.class);

        // Let's start with DSS...

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user.p12"), new PasswordProtection("ks-password".toCharArray()));

        final DSSPrivateKeyEntry dssPrivateKeyEntry = token.getKey("good-user");

        final DataToSignOneDocumentDTO dataToSign = new DataToSignOneDocumentDTO();

        final RemoteSignatureParameters parameters = new RemoteSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        parameters.setSigningCertificate(new RemoteCertificate(dssPrivateKeyEntry.getCertificate().getEncoded()));
        dataToSign.setParameters(parameters);

        final RemoteDocument toSignDocument = new RemoteDocument();
        toSignDocument.setBytes("Hello CEF!".getBytes("UTF-8"));
        dataToSign.setToSignDocument(toSignDocument);

        // get data to sign

        final ToBeSignedDTO toBeSignedDTO = restClient.getDataToSign(dataToSign);
        assertNotNull(toBeSignedDTO);

        // sign locally
        final SignatureValue signatureValue = token.sign(DTOConverter.toToBeSigned(toBeSignedDTO), parameters.getDigestAlgorithm(), dssPrivateKeyEntry);
        assertNotNull(signatureValue);

        final SignOneDocumentDTO signOneDoc = new SignOneDocumentDTO();
        signOneDoc.setToSignDocument(toSignDocument);
        signOneDoc.setParameters(parameters);
        signOneDoc.setSignatureValue(DTOConverter.toSignatureValueDTO(signatureValue));

        // sign document

        final RemoteDocument signedDocument = restClient.signDocument(signOneDoc);
        assertNotNull(signedDocument);
        assertNotNull(signedDocument.getBytes());
    }

}

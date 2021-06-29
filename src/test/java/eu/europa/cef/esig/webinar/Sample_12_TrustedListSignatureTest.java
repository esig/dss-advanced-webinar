package eu.europa.cef.esig.webinar;

import java.io.File;
import java.security.KeyStore.PasswordProtection;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class Sample_12_TrustedListSignatureTest {

    @Test
    void signTrustedList() throws Exception {

        // Sign a TL with the SignatureParametersBuilder

        final FileDocument document = new FileDocument("src/test/resources/sample_12/unsigned_TL.xml");

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("good-user");

        final XAdESService service = new XAdESService(new CommonCertificateVerifier());

        final TrustedListSignatureParametersBuilder paramsBuilder = new TrustedListSignatureParametersBuilder(key.getCertificate(), document);
        final XAdESSignatureParameters parameters = paramsBuilder.build();

        final ToBeSigned dataToSign = service.getDataToSign(document, parameters);
        final SignatureValue signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), key);
        final DSSDocument signDocument = service.signDocument(document, parameters, signatureValue);
        signDocument.save("target/signed_TL.xml");
    }

}

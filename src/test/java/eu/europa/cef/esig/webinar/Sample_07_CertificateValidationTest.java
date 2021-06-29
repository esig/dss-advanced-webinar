package eu.europa.cef.esig.webinar;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;

public class Sample_07_CertificateValidationTest {

    @Test
    void validation() throws IOException {

        final CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/pki-files/revoked-user.crt"));

        final CertificateValidator validator = CertificateValidator.fromCertificate(certificate);

        final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        certificateVerifier.setDataLoader(new CommonsDataLoader());

        final CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.importAsTrusted(new KeyStoreCertificateSource("src/test/resources/pki-files/trust-anchors.jks", "JKS", "ks-password"));
        certificateVerifier.setTrustedCertSources(trustedCertSource);
        validator.setCertificateVerifier(certificateVerifier);

        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_REVOCATION_DATA);

        // final CertificateReports reports =
        // validator.validate(ValidationPolicyFacade.newFacade().getDefaultValidationPolicy());
        final CertificateReports reports = validator.validate();

        reports.print();
    }

}

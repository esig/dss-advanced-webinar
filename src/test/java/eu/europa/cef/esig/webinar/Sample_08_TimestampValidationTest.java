package eu.europa.cef.esig.webinar;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class Sample_08_TimestampValidationTest {

    @Test
    void validation() throws IOException {

        final DSSDocument doc = new InMemoryDocument("Hello CEF!".getBytes());

        final OnlineTSPSource tspSource = new OnlineTSPSource("http://dss.nowina.lu/pki-factory/tsa/good-tsa");
        final TimestampBinary timestampBinary = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, doc));

        final DSSDocument timestampDoc = new InMemoryDocument(timestampBinary.getBytes());

        final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(timestampDoc);
        //		final DetachedTimestampValidator validator = new DetachedTimestampValidator(timestampDoc);
        validator.setDetachedContents(Arrays.asList(doc));

        final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        certificateVerifier.setDataLoader(new CommonsDataLoader());

        final CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.importAsTrusted(new KeyStoreCertificateSource("src/test/resources/pki-files/trust-anchors.jks", "JKS", "ks-password"));
        certificateVerifier.setTrustedCertSources(trustedCertSource);

        validator.setCertificateVerifier(certificateVerifier);

        final Reports reports = validator.validateDocument();

        reports.print();
    }

}

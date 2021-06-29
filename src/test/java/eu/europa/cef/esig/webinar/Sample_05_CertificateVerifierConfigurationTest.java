package eu.europa.cef.esig.webinar;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class Sample_05_CertificateVerifierConfigurationTest {

    @Test
    void noRevocationAlerting() throws IOException {
        final InMemoryDocument doc = new InMemoryDocument("Hello CEF!".getBytes());

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user-no-revocation.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("good-user-no-revocation");

        final OnlineTSPSource tspSource = new OnlineTSPSource();
        tspSource.setTspServer("http://dss.nowina.lu/pki-factory/tsa/good-tsa");

        final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

        final CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.importAsTrusted(new KeyStoreCertificateSource("src/test/resources/pki-files/trust-anchors.jks", "JKS", "ks-password"));

        certificateVerifier.setTrustedCertSources(trustedCertSource);
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        certificateVerifier.setCrlSource(new OnlineCRLSource());

        certificateVerifier.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());

        // certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert());
        // certificateVerifier.setAlertOnMissingRevocationData(new
        // SilentOnStatusAlert());

        final XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(tspSource);

        final XAdESSignatureParameters params = new XAdESSignatureParameters();
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        final ToBeSigned dataToSign = service.getDataToSign(doc, params);
        final SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);
        assertThrows(AlertException.class, () -> service.signDocument(doc, params, signatureValue));
    }

    @Test
    void revokedUser() throws IOException {
        final InMemoryDocument doc = new InMemoryDocument("Hello CEF!".getBytes());

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/revoked-user.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("revoked-user");

        final OnlineTSPSource tspSource = new OnlineTSPSource();
        tspSource.setTspServer("http://dss.nowina.lu/pki-factory/tsa/good-tsa");

        final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

        final CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.importAsTrusted(new KeyStoreCertificateSource("src/test/resources/pki-files/trust-anchors.jks", "JKS", "ks-password"));

        certificateVerifier.setTrustedCertSources(trustedCertSource);
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        certificateVerifier.setCrlSource(new OnlineCRLSource());

        certificateVerifier.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());

        // certificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert());
        // certificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());

        final XAdESService service = new XAdESService(certificateVerifier);
        service.setTspSource(tspSource);

        final XAdESSignatureParameters params = new XAdESSignatureParameters();
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        final ToBeSigned dataToSign = service.getDataToSign(doc, params);
        final SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);
        assertThrows(AlertException.class, () -> service.signDocument(doc, params, signatureValue));
    }

    void additionalConfigurations() {

        final CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

        // Detects broken timestamp(s)
        certificateVerifier.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());

        // Detects missing revocation data after the last usage of a TSU
        certificateVerifier.setAlertOnUncoveredPOE(new ExceptionOnStatusAlert());

        // Detects missing "fresh" revocation data after the best signing time
        // (validation time / earliest signature timestamp time)
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());

        // Forces DSS to request revocation data for untrusted certificate(s)
        certificateVerifier.setCheckRevocationForUntrustedChains(true);

        // 5.9+ : Detects expired signatures (no timestamp/revocation data in time to
        // chain until the validation/current time)
        // certificateVerifier.setAlertOnExpiredSignature(new ExceptionOnStatusAlert());

        // 5.9+ : Specify the order for the revocation check (OCSP and then CRL by
        // default)
        // certificateVerifier.setRevocationDataLoadingStrategy(new
        // OCSPFirstRevocationDataLoadingStrategy());
        // certificateVerifier.setRevocationDataLoadingStrategy(new
        // CRLFirstRevocationDataLoadingStrategy());

    }

}

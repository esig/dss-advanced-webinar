package eu.europa.cef.esig.webinar;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class Sample_11_DigestSignatureTest {

    private static final Logger LOG = LoggerFactory.getLogger(Sample_11_DigestSignatureTest.class);

    @Test
    void digestSignatureXAdESandECDSA() throws IOException {

        final DSSDocument fullDocument = new FileDocument("src/test/resources/sample_11/original.txt");

        final DigestDocument digestedDocument = new DigestDocument(DigestAlgorithm.SHA512, fullDocument.getDigest(DigestAlgorithm.SHA512));

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-ecdsa-user.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("good-ecdsa-user");

        final XAdESSignatureParameters params = new XAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        params.setSignaturePackaging(SignaturePackaging.DETACHED);
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());
        params.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);

        final XAdESService service = new XAdESService(new CommonCertificateVerifier());

        final ToBeSigned dataToSign = service.getDataToSign(digestedDocument, params);

        LOG.info("ToBeSigned with XAdES is a XML (canonicalized SignedInfo content) : \n\n{}\n\n", new String(dataToSign.getBytes()));

        // Signature = digest + encryption on the token side
        // SignatureValue signatureValue = token.sign(dataToSign,
        // params.getDigestAlgorithm(), key);

        // Signature = externalized digest + encryption on the token side (raw signature
        // or NONEwithXXX)

        final byte[] preComputedDigest = DSSUtils.digest(params.getDigestAlgorithm(), dataToSign.getBytes());
        final Digest digest = new Digest(params.getDigestAlgorithm(), preComputedDigest);

        LOG.info("Digest to be signed : {}", digest);

        final SignatureValue signatureValue = token.signDigest(digest, key);

        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, key.getCertificate()));

        final DSSDocument signDocument = service.signDocument(digestedDocument, params, signatureValue);
        assertNotNull(signDocument);
        signDocument.save("target/xades.xml");
    }

    @Test
    void digestSignatureCAdESandRSA() throws IOException {

        final DSSDocument fullDocument = new FileDocument("src/test/resources/sample_11/original.txt");

        final DigestDocument digestedDocument = new DigestDocument(DigestAlgorithm.SHA512, fullDocument.getDigest(DigestAlgorithm.SHA512));

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("good-user");

        final CAdESSignatureParameters params = new CAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        params.setSignaturePackaging(SignaturePackaging.DETACHED);
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());
        params.setReferenceDigestAlgorithm(DigestAlgorithm.SHA512);
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);

        final CAdESService service = new CAdESService(new CommonCertificateVerifier());

        final ToBeSigned dataToSign = service.getDataToSign(digestedDocument, params);

        // Signature = digest + encryption on the token side
        // SignatureValue signatureValue = token.sign(dataToSign,
        // params.getDigestAlgorithm(), key);

        // Signature = externalized digest + encryption on the token side (raw signature
        // or NONEwithXXX)

        final byte[] preComputedDigest = DSSUtils.digest(params.getDigestAlgorithm(), dataToSign.getBytes());
        final byte[] encodeRSADigest = DSSUtils.encodeRSADigest(params.getDigestAlgorithm(), preComputedDigest); // ASN1 encoding of the digest
        final Digest digest = new Digest(params.getDigestAlgorithm(), encodeRSADigest);

        final SignatureValue signatureValue = token.signDigest(digest, key);

        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, key.getCertificate()));

        final DSSDocument signDocument = service.signDocument(digestedDocument, params, signatureValue);
        assertNotNull(signDocument);
        signDocument.save("target/cades.pkcs7");
    }

}

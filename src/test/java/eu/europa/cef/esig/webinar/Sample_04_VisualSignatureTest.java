package eu.europa.cef.esig.webinar;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.security.KeyStore.PasswordProtection;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class Sample_04_VisualSignatureTest {

    @Test
    void visualSignature() throws Exception {

        final FileDocument doc = new FileDocument("src/test/resources/sample_04/hello.pdf");

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("good-user");

        final PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());
        params.setLocation("Luxembourg");

        final SignatureImageParameters imageParams = new SignatureImageParameters();

        final SignatureFieldParameters fieldParams = new SignatureFieldParameters();
        fieldParams.setPage(1);
        fieldParams.setOriginX(70);
        fieldParams.setOriginY(150);
        imageParams.setFieldParameters(fieldParams);

        final SignatureImageTextParameters textParams = new SignatureImageTextParameters();
        textParams.setText("Signed by: " + DSSASN1Utils.getHumanReadableName(key.getCertificate()));
        textParams.setTextColor(Color.BLUE);
        textParams.setFont(new DSSJavaFont(new Font(Font.SANS_SERIF, Font.ITALIC, 12)));
        imageParams.setTextParameters(textParams);
        params.setImageParameters(imageParams);

        final PAdESService service = new PAdESService(new CommonCertificateVerifier());

        final ToBeSigned dataToSign = service.getDataToSign(doc, params);
        final SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);
        final DSSDocument signDocument = service.signDocument(doc, params, signatureValue);

        signDocument.save("target/visual-signature.pdf");
    }

    @Test
    void visualSignatureTextAndLogo() throws Exception {

        final FileDocument doc = new FileDocument("src/test/resources/sample_04/hello.pdf");

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("good-user");

        final PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());
        params.setLocation("Luxembourg");

        final SignatureImageParameters imageParams = new SignatureImageParameters();

        final SignatureFieldParameters fieldParams = new SignatureFieldParameters();
        fieldParams.setPage(1);
        fieldParams.setOriginX(70);
        fieldParams.setOriginY(150);
        imageParams.setFieldParameters(fieldParams);

        imageParams.setImage(new FileDocument("src/test/resources/sample_04/logo.jpg")); // Added

        final SignatureImageTextParameters textParams = new SignatureImageTextParameters();
        textParams.setText("Signed by: " + DSSASN1Utils.getHumanReadableName(key.getCertificate()));
        textParams.setTextColor(new Color(0, 69, 131)); // Use same color than in the logo
        textParams.setFont(new DSSJavaFont(new Font(Font.SANS_SERIF, Font.ITALIC, 12)));
        textParams.setSignerTextPosition(SignerTextPosition.RIGHT); // Added
        textParams.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.MIDDLE); // Added
        imageParams.setTextParameters(textParams);

        params.setImageParameters(imageParams);

        final PAdESService service = new PAdESService(new CommonCertificateVerifier());
        //        service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
        service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());

        final ToBeSigned dataToSign = service.getDataToSign(doc, params);
        final SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);
        final DSSDocument signDocument = service.signDocument(doc, params, signatureValue);

        signDocument.save("target/visual-signature-with-logo.pdf");
    }

    @Test
    void externalFont() throws Exception {

        final FileDocument doc = new FileDocument("src/test/resources/sample_04/hello.pdf");

        final Pkcs12SignatureToken token = new Pkcs12SignatureToken(new File("src/test/resources/pki-files/good-user.p12"), new PasswordProtection("ks-password".toCharArray()));
        final DSSPrivateKeyEntry key = token.getKey("good-user");

        final PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        params.setSigningCertificate(key.getCertificate());
        params.setCertificateChain(key.getCertificateChain());
        params.setLocation("Luxembourg");

        final SignatureImageParameters imageParams = new SignatureImageParameters();

        final SignatureFieldParameters fieldParams = new SignatureFieldParameters();
        fieldParams.setPage(1);
        fieldParams.setOriginX(70);
        fieldParams.setOriginY(150);
        imageParams.setFieldParameters(fieldParams);

        final SignatureImageTextParameters textParams = new SignatureImageTextParameters();
        textParams.setText("Signed by: " + DSSASN1Utils.getHumanReadableName(key.getCertificate()));
        textParams.setTextColor(Color.BLUE);
        textParams.setFont(new DSSFileFont(new FileDocument("src/test/resources/sample_04/Pacifico.ttf"))); // Added external font
        imageParams.setTextParameters(textParams);
        params.setImageParameters(imageParams);

        final PAdESService service = new PAdESService(new CommonCertificateVerifier());

        final ToBeSigned dataToSign = service.getDataToSign(doc, params);
        final SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);
        final DSSDocument signDocument = service.signDocument(doc, params, signatureValue);

        signDocument.save("target/visual-signature-pacifico.pdf");
    }

}

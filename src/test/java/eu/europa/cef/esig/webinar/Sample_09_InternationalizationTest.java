package eu.europa.cef.esig.webinar;

import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class Sample_09_InternationalizationTest {

	private static final Logger LOG = LoggerFactory.getLogger(Sample_09_InternationalizationTest.class);

	@Test
	void validation() {

		final FileDocument doc = new FileDocument("src/test/resources/sample_09/hello-signed-pades-baseline-b.pdf");

		final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);

		validator.setCertificateVerifier(new CommonCertificateVerifier());

		// DSS will use dss-messages_hu.properties file from the classpath to translate
		// the different messages of the detailed report
		validator.setLocale(new Locale("HU"));

		final Reports reports = validator.validateDocument();

		LOG.info(reports.getXmlDetailedReport());
	}

}

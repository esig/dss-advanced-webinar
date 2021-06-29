package eu.europa.cef.esig.webinar;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;

import javax.xml.transform.Result;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamResult;

import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.MimeConstants;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class Sample_02_ReportGenerationTest {

	@Test
	void generateHTML_PDF_reports() throws Exception {

		// Loads an existing diagnostic data
		final XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/sample_02/diagnostic-data.xml"));
		assertNotNull(diagnosticData);

		// Replays the validation
		final DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(ValidationPolicyFacade.newFacade().getDefaultValidationPolicy());

		// Gets the 3 reports
		final Reports reports = executor.execute();
		assertNotNull(reports);
		assertNotNull(reports.getXmlSimpleReport());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getXmlValidationReport());

		// JAXB representation of the detailed report
		final XmlDetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();

		// Wrapper to ease the JAXB navigation
		// final DetailedReport detailedReport = reports.getDetailedReport();
		// detailedReport.getXmlSignatureById("");
		// detailedReport.getXmlTimestampById("");
		// detailedReport.getXmlCertificateById("");

		// Generated the HTML report (CSS with Bootstrap)
		try (FileOutputStream fos = new FileOutputStream("target/detailed-report.html")) {
			DetailedReportFacade.newFacade().generateHtmlReport(detailedReportJaxb, new StreamResult(fos));
		}

		// Generates the PDF report with Apache FOP
		final FopFactory fopFactory = FopFactory.newInstance(new File(".").toURI());
		try (FileOutputStream fos = new FileOutputStream("target/detailed-report.pdf")) {
			final Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, fos);
			final Result result = new SAXResult(fop.getDefaultHandler());
			DetailedReportFacade.newFacade().generatePdfReport(detailedReportJaxb, result);
		}

	}

}

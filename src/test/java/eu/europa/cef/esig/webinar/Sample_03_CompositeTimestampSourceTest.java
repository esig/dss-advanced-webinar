package eu.europa.cef.esig.webinar;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class Sample_03_CompositeTimestampSourceTest {

	@Test
	void basicConfiguration() {

		final FileDocument doc = new FileDocument("src/test/resources/sample_03/hello.pdf");

		final OnlineTSPSource badSource = new OnlineTSPSource();
		badSource.setTspServer("http://dss.nowina.lu/pki-factory/tsa/error-500/good-tsa"); // TSA which always fails
		badSource.setDataLoader(new TimestampDataLoader());

		final PAdESService service = new PAdESService(new CommonCertificateVerifier());
		service.setTspSource(badSource);

		// Default digest algorithm for message-imprint : DigestAlgorithm.SHA256
		assertThrows(DSSExternalResourceException.class, () -> service.timestamp(doc, new PAdESTimestampParameters()));
	}

	@Test
	void fallbackWithMultipleSources() throws Exception {

		// Composite source with several timestamp sources

		final Map<String, TSPSource> sources = new HashMap<>();

		final OnlineTSPSource firstTSPSource = new OnlineTSPSource();
		firstTSPSource.setTspServer("http://dss.nowina.lu/pki-factory/tsa/error-500/good-tsa"); // TSA which always fails
		firstTSPSource.setDataLoader(new TimestampDataLoader());
		sources.put("first", firstTSPSource);

		final OnlineTSPSource secondTSPSource = new OnlineTSPSource();
		secondTSPSource.setTspServer("http://dss.nowina.lu/pki-factory/tsa/good-tsa");
		secondTSPSource.setDataLoader(new TimestampDataLoader());
		secondTSPSource.setNonceSource(new SecureRandomNonceSource());
		sources.put("second", secondTSPSource);

		// sources.put("third", ...);

		final CompositeTSPSource compositeSource = new CompositeTSPSource();
		compositeSource.setTspSources(sources);

		final FileDocument doc = new FileDocument("src/test/resources/sample_03/hello.pdf");

		final PAdESService service = new PAdESService(new CommonCertificateVerifier());
		service.setTspSource(compositeSource);

		// All sources must support a same common digest algorithm
		final DSSDocument timestampedDoc = service.timestamp(doc, new PAdESTimestampParameters(DigestAlgorithm.SHA512));
		assertNotNull(timestampedDoc);
		timestampedDoc.save("target/timestamped.pdf");
	}

}

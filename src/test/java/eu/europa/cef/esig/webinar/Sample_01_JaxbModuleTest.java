package eu.europa.cef.esig.webinar;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.util.List;

import javax.xml.bind.UnmarshalException;
import javax.xml.transform.stream.StreamSource;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.TrustedListUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class Sample_01_JaxbModuleTest {

	private static final Logger LOG = LoggerFactory.getLogger(Sample_01_JaxbModuleTest.class);

	@Test
	void loadEditValidTrustedList() throws Exception {

		final File file = new File("src/test/resources/sample_01/fi-tl.xml");

		final TrustStatusListType jaxbObject = TrustedListFacade.newFacade().unmarshall(file);

		assertNotNull(jaxbObject);

		// modify JAXB Objects
		jaxbObject.getSchemeInformation().setTSLSequenceNumber(new BigInteger("39"));

		// remove existing signature
		jaxbObject.setSignature(null);

		DSSDocument modifiedUnsignedTL = null;

		try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			TrustedListFacade.newFacade().marshall(jaxbObject, baos);
			modifiedUnsignedTL = new InMemoryDocument(baos.toByteArray());
		}

		LOG.info("Modified TL \n{}", new String(DSSUtils.toByteArray(modifiedUnsignedTL)));

		modifiedUnsignedTL.save("target/unsigned_TL.xml");
	}

	@Test
	void loadNonConformTrustedList() throws Exception {

		// Above TL with commented version
		final File file = new File("src/test/resources/sample_01/fi-tl-broken.xml");

		// Default configuration with conformance validation

		final UnmarshalException exception = assertThrows(UnmarshalException.class, () -> {

			TrustedListFacade.newFacade().unmarshall(file);

		});
		LOG.info("Invalid XML details", exception);

		// By pass the validation and load the JAXB Object

		final TrustStatusListType jaxbObject = TrustedListFacade.newFacade().unmarshall(file, false);
		assertNotNull(jaxbObject);
		assertNull(jaxbObject.getSchemeInformation().getTSLVersionIdentifier());

		// Fix the TL and add the missing version

		jaxbObject.getSchemeInformation().setTSLVersionIdentifier(new BigInteger("5"));

		String xmlTrustedList = TrustedListFacade.newFacade().marshall(jaxbObject);
		assertNotNull(xmlTrustedList);
	}

	@Test
	void validateAgainstXSD() {

		final File validFile = new File("src/test/resources/sample_01/fi-tl.xml");
		List<String> errorMessages = TrustedListUtils.getInstance().validateAgainstXSD(new StreamSource(validFile));
		assertTrue(errorMessages.isEmpty());

		final File invalidFile = new File("src/test/resources/sample_01/fi-tl-broken.xml");
		errorMessages = TrustedListUtils.getInstance().validateAgainstXSD(new StreamSource(invalidFile));
		assertFalse(errorMessages.isEmpty());

		LOG.info("Errors : {}", errorMessages);
	}

}

package eu.europa.cef.esig.webinar;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.apache.http.conn.ssl.TrustAllStrategy;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogLOTLLocationChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogOJUrlChangeAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class Sample_06_TrustAnchorConfigurationTest {

    private static final Logger LOG = LoggerFactory.getLogger(Sample_06_TrustAnchorConfigurationTest.class);

    // https://ec.europa.eu/cefdigital/DSS/webapp-demo/doc/dss-documentation.html#_trust_anchors_configuration

    // https://ec.europa.eu/cefdigital/DSS/webapp-demo/doc/dss-documentation.html#tlValidationJob

    @Test
    void trustAnchorConfiguration() throws IOException {

        final CertificateVerifier cv = new CommonCertificateVerifier();

        cv.setTrustedCertSources(this.trustStoreSource(), this.manualCertSource(), this.trustedListSource());

        assertTrue(cv.getTrustedCertSources().getNumberOfCertificates() > 0);

    }

    CertificateSource trustStoreSource() throws IOException {
        final CommonTrustedCertificateSource trustedSource = new CommonTrustedCertificateSource();
        trustedSource.importAsTrusted(new KeyStoreCertificateSource("src/test/resources/pki-files/trust-anchors.jks", "JKS", "ks-password"));
        return trustedSource;
    }

    CertificateSource manualCertSource() throws IOException {
        final CommonTrustedCertificateSource trustedSource = new CommonTrustedCertificateSource();
        trustedSource.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/sample_06/root-ca.crt")));
        return trustedSource;
    }

    CertificateSource trustedListSource() {

        final TrustedListsCertificateSource certSource = new TrustedListsCertificateSource();

        this.job(certSource).onlineRefresh();

        return certSource;
    }

    TLValidationJob job(final TrustedListsCertificateSource certSource) {
        final TLValidationJob job = new TLValidationJob();
        job.setDebug(true);
        job.setOnlineDataLoader(this.onlineLoader());
        job.setOfflineDataLoader(this.offlineLoader());
        job.setTrustedListCertificateSource(certSource);
        job.setSynchronizationStrategy(new AcceptAllStrategy());

        final LOTLSource europeanLOTL = this.europeanLOTL();
        job.setListOfTrustedListSources(europeanLOTL);

        // job.setTrustedListSources(independantTL);

        job.setLOTLAlerts(Arrays.asList(this.ojUrlAlert(europeanLOTL), this.lotlLocationAlert(europeanLOTL)));
        job.setTLAlerts(Arrays.asList(this.tlSigningAlert(), this.tlExpirationDetection()));

        return job;
    }

    public LOTLSource europeanLOTL() {
        final LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl("https://ec.europa.eu/tools/lotl/eu-lotl.xml");
        lotlSource.setCertificateSource(this.officialJournalContentKeyStore());
        lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG"));
        lotlSource.setPivotSupport(true);

        // Only loads the Spanish trusted list from the LOTL
        //		lotlSource.setTlPredicate(new SchemeTerritoryOtherTSLPointer("ES").and(new XMLOtherTSLPointer()));

        // Only loads the trust service provider with the given name from the selected TL
        //		lotlSource.setTrustServiceProviderPredicate(new TrustServiceProviderByTSPName("VIAFIRMA, S.L."));

        // Only loads trust services have a granted status (or equivalent) in its history from the selected TSP
        //		lotlSource.setTrustServicePredicate(new GrantedTrustService());

        return lotlSource;
    }

    public CertificateSource officialJournalContentKeyStore() {
        try {
            return new KeyStoreCertificateSource(new File("src/test/resources/sample_06/oj-content.p12"), "PKCS12", "dss-password");
        } catch (final IOException e) {
            throw new DSSException("Unable to load the keystore", e);
        }
    }

    public DSSFileLoader onlineLoader() {
        final FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader();
        onlineFileLoader.setCacheExpirationTime(0);
        onlineFileLoader.setDataLoader(this.dataLoader());
        onlineFileLoader.setFileCacheDirectory(this.tlCacheDirectory());
        return onlineFileLoader;
    }

    public DSSFileLoader offlineLoader() {
        final FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
        offlineFileLoader.setDataLoader(new IgnoreDataLoader());
        offlineFileLoader.setFileCacheDirectory(this.tlCacheDirectory());
        return offlineFileLoader;
    }

    public File tlCacheDirectory() {
        final File rootFolder = new File("target");
        final File tslCache = new File(rootFolder, "dss-tsl-loader");
        if (tslCache.mkdirs()) {
            LOG.info("TL Cache folder : {}", tslCache.getAbsolutePath());
        }
        return tslCache;
    }

    public CommonsDataLoader dataLoader() {
        final CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
        commonsDataLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);
        return commonsDataLoader;
    }

    // Optionally : alerting.
    // Recommended detections : OJUrlChangeDetection + LOTLLocationChangeDetection

    public TLAlert tlSigningAlert() {
        final TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();
        final LogTLSignatureErrorAlertHandler handler = new LogTLSignatureErrorAlertHandler();
        return new TLAlert(signingDetection, handler);
    }

    public TLAlert tlExpirationDetection() {
        final TLExpirationDetection expirationDetection = new TLExpirationDetection();
        final LogTLExpirationAlertHandler handler = new LogTLExpirationAlertHandler();
        return new TLAlert(expirationDetection, handler);
    }

    public LOTLAlert ojUrlAlert(final LOTLSource source) {
        final OJUrlChangeDetection ojUrlDetection = new OJUrlChangeDetection(source);
        final LogOJUrlChangeAlertHandler handler = new LogOJUrlChangeAlertHandler();
        return new LOTLAlert(ojUrlDetection, handler);
    }

    public LOTLAlert lotlLocationAlert(final LOTLSource source) {
        final LOTLLocationChangeDetection lotlLocationDetection = new LOTLLocationChangeDetection(source);
        final LogLOTLLocationChangeAlertHandler handler = new LogLOTLLocationChangeAlertHandler();
        return new LOTLAlert(lotlLocationDetection, handler);
    }

}

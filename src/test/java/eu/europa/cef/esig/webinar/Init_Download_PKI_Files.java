package eu.europa.cef.esig.webinar;

import java.io.FileOutputStream;
import java.io.IOException;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;

public class Init_Download_PKI_Files {

    /**
     * We download resources from the server http://dss.nowina.lu/pki-factory/
     * That's a test PKI which is re-generated from time to time
     *
     * @throws IOException
     */
    public static void main(final String[] args) throws IOException {

        final CommonsDataLoader dataLoader = new CommonsDataLoader();

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/pki-files/good-ecdsa-user.p12")) {
            fos.write(dataLoader.get("http://dss.nowina.lu/pki-factory/keystore/good-ecdsa-user.p12"));
        }

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/pki-files/good-user.p12")) {
            fos.write(dataLoader.get("http://dss.nowina.lu/pki-factory/keystore/good-user.p12"));
        }

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/pki-files/good-user-no-revocation.p12")) {
            fos.write(dataLoader.get("http://dss.nowina.lu/pki-factory/keystore/good-user-no-revocation.p12"));
        }

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/pki-files/revoked-user.p12")) {
            fos.write(dataLoader.get("http://dss.nowina.lu/pki-factory/keystore/revoked-user.p12"));
        }

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/pki-files/revoked-user.crt")) {
            fos.write(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/revoked-user.crt"));
        }

        try (FileOutputStream fos = new FileOutputStream("src/test/resources/pki-files/trust-anchors.jks")) {
            fos.write(dataLoader.get("http://dss.nowina.lu/pki-factory/keystore/trust-anchors.jks"));
        }

    }

}

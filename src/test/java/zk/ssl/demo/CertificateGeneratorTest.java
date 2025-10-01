package zk.ssl.demo;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class CertificateGeneratorTest {

	private final String testKeystore = "test.p12";
	private final String testPassword = "testpass";

	@AfterEach
	void cleanup() {
		new File(testKeystore).delete();
	}

	@Test
	void shouldGenerateSelfSignedCertificate() throws Exception {
		CertificateGenerator.generateSelfSignedCert(testKeystore, testPassword);

		File keystoreFile = new File(testKeystore);
		assertThat(keystoreFile).exists();
		assertThat(keystoreFile.length()).isGreaterThan(0);
	}

	@Test
	void shouldCreateValidCertificate() throws Exception {
		CertificateGenerator.generateSelfSignedCert(testKeystore, testPassword);

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(testKeystore)) {
			keyStore.load(fis, testPassword.toCharArray());
		}

		// Use the correct alias from CertificateGenerator
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(CertificateGenerator.KEYSTORE_ALIAS);

		assertThat(cert).isNotNull();
		assertThat(cert.getSubjectX500Principal().getName()).contains("CN=localhost");
		assertThat(cert.getIssuerX500Principal().getName()).contains("CN=localhost");
		assertThat(cert.getSigAlgName()).isEqualTo("SHA256withECDSA");
		assertThat(cert.getSubjectAlternativeNames()).isNotNull();

		// Additional assertions for the secure certificate
		assertThat(cert.getSubjectX500Principal().getName()).contains("L=Dhaka");
		assertThat(cert.getSubjectX500Principal().getName()).contains("C=BD");
		assertThat(cert.getPublicKey().getAlgorithm()).isEqualTo("EC");

		// Check key size for RSA
		if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsaKey) {
			assertThat(rsaKey.getModulus().bitLength()).isEqualTo(4096);
		}
	}

	@Test
	void shouldCreateSelfSignedCertificate() throws Exception {
		CertificateGenerator.generateSelfSignedCert(testKeystore, testPassword);

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(testKeystore)) {
			keyStore.load(fis, testPassword.toCharArray());
		}

		// Use the correct alias from CertificateGenerator
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(CertificateGenerator.KEYSTORE_ALIAS);

		assertThat(cert).isNotNull();
		assertThat(cert.getSubjectX500Principal())
				.isEqualTo(cert.getIssuerX500Principal());
	}

	@Test
	void shouldHaveValidityPeriod() throws Exception {
		CertificateGenerator.generateSelfSignedCert(testKeystore, testPassword);

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(testKeystore)) {
			keyStore.load(fis, testPassword.toCharArray());
		}

		X509Certificate cert = (X509Certificate) keyStore.getCertificate(CertificateGenerator.KEYSTORE_ALIAS);

		assertThat(cert).isNotNull();
		assertThat(cert.getNotBefore()).isNotNull();
		assertThat(cert.getNotAfter()).isNotNull();
		assertThat(cert.getNotAfter()).isAfter(cert.getNotBefore());

		// Check that validity is approximately 2 years
		long validityPeriod = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
		long twoYearsInMs = 2L * 365 * 24 * 60 * 60 * 1000;
		assertThat(validityPeriod).isBetween(twoYearsInMs - 86400000L, twoYearsInMs + 86400000L); // ±1 day tolerance
	}

	@Test
	void shouldHaveCorrectExtensions() throws Exception {
		CertificateGenerator.generateSelfSignedCert(testKeystore, testPassword);

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(testKeystore)) {
			keyStore.load(fis, testPassword.toCharArray());
		}

		X509Certificate cert = (X509Certificate) keyStore.getCertificate(CertificateGenerator.KEYSTORE_ALIAS);

		assertThat(cert).isNotNull();

		// Check Subject Alternative Names
		assertThat(cert.getSubjectAlternativeNames()).isNotNull();
		assertThat(cert.getSubjectAlternativeNames()).isNotEmpty();

		// Check Key Usage
		assertThat(cert.getKeyUsage()).isNotNull();
		assertThat(cert.getKeyUsage()[0]).isTrue(); // digitalSignature
		assertThat(cert.getKeyUsage()[2]).isTrue(); // keyEncipherment

		// Check Extended Key Usage
		assertThat(cert.getExtendedKeyUsage()).isNotNull();
		assertThat(cert.getExtendedKeyUsage()).contains("1.3.6.1.5.5.7.3.1"); // serverAuth
	}
}
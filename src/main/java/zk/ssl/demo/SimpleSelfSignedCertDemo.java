package zk.ssl.demo;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Objects;

public class SimpleSelfSignedCertDemo {

	private static final String KEYSTORE_ALIAS = "secure-demo";

	public static void main(String[] args) {
		try {
			String keystorePath = "demo.p12";
			String password = "changeit";

			System.out.println("Generating secure self-signed certificate...");
			CertificateGenerator.generateSelfSignedCert(keystorePath, password);

			System.out.println("Certificate generated: " + keystorePath);

			displayCertificateInfo(keystorePath, password);

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace();
		}
	}

	private static void displayCertificateInfo(String keystorePath, String password) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(keystorePath)) {
			keyStore.load(fis, password.toCharArray());
		}

		System.out.println("Available aliases: " + java.util.Collections.list(keyStore.aliases()));
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEYSTORE_ALIAS);
		if (Objects.isNull(cert)) {
			System.err.println("Certificate not found with alias: " + KEYSTORE_ALIAS);
			return;
		}

		System.out.println("\nCertificate Info:");
		System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
		System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());
		System.out.println("Valid from: " + cert.getNotBefore());
		System.out.println("Valid to: " + cert.getNotAfter());
		System.out.println("Algorithm: " + cert.getSigAlgName());
		System.out.println("Key Algorithm: " + cert.getPublicKey().getAlgorithm());

		// Display key size
		if (cert.getPublicKey().getAlgorithm().equals("RSA")) {
			java.security.interfaces.RSAPublicKey rsaKey =
					(java.security.interfaces.RSAPublicKey) cert.getPublicKey();
			System.out.println("Key Size: " + rsaKey.getModulus().bitLength() + " bits");
		} else if (cert.getPublicKey().getAlgorithm().equals("EC")) {
			java.security.interfaces.ECPublicKey ecKey =
					(java.security.interfaces.ECPublicKey) cert.getPublicKey();
			System.out.println("EC Curve: " + ecKey.getParams().toString());
		}

		if (cert.getSubjectAlternativeNames() != null) {
			System.out.println("SAN: " + cert.getSubjectAlternativeNames());
		}

		// Display fingerprint
		java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
		byte[] fingerprint = md.digest(cert.getEncoded());
		System.out.println("SHA-256 Fingerprint: " + bytesToHex(fingerprint));
	}

	private static String bytesToHex(byte[] bytes) {
		return HexFormat.of().formatHex(bytes).toUpperCase();
	}
}
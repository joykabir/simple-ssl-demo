package zk.ssl.demo;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class CertificateGenerator {

	public static final String KEYSTORE_ALIAS = "secure-demo"; // Public constant for consistency

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void generateSelfSignedCert(String keystorePath, String password) throws Exception {
		KeyPair keyPair = generateSecureKeyPair();
		X509Certificate cert = createSecureCertificate(keyPair);
		saveToKeystore(keystorePath, password, keyPair.getPrivate(), cert);
	}

	private static KeyPair generateSecureKeyPair() throws Exception {
		return generateECKeyPair();
		// For RSA, uncomment the following line and comment the EC line above
		// return generateRSAKeyPair();
	}

	private static KeyPair generateRSAKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		SecureRandom secureRandom = SecureRandom.getInstanceStrong();
		keyGen.initialize(4096, secureRandom);
		return keyGen.generateKeyPair();
	}

	private static KeyPair generateECKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
		SecureRandom secureRandom = SecureRandom.getInstanceStrong();
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
		keyGen.initialize(ecSpec, secureRandom);
		return keyGen.generateKeyPair();
	}

	private static X509Certificate createSecureCertificate(KeyPair keyPair) throws Exception {
		LocalDateTime now = LocalDateTime.now();
		Date notBefore = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
		Date notAfter = Date.from(now.plusYears(2).atZone(ZoneId.systemDefault()).toInstant());

		X500Name subject = new X500Name("CN=localhost, OU=SecureDemo, O=SSL Demo Corp, L=Dhaka, ST=Dhaka, C=BD");
		BigInteger serial = generateSecureSerial();

		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				subject, serial, notBefore, notAfter, subject, keyPair.getPublic());

		addSecureExtensions(certBuilder, keyPair.getPublic());

		String signatureAlgorithm = getSignatureAlgorithm(keyPair.getPublic());
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
				.setProvider("BC").build(keyPair.getPrivate());

		X509CertificateHolder certHolder = certBuilder.build(signer);

		return new JcaX509CertificateConverter()
				.setProvider("BC").getCertificate(certHolder);
	}

	private static BigInteger generateSecureSerial() throws Exception {
		SecureRandom secureRandom = SecureRandom.getInstanceStrong();
		return new BigInteger(160, secureRandom);
	}

	private static String getSignatureAlgorithm(PublicKey publicKey) {
		if (publicKey.getAlgorithm().equals("RSA")) {
			return "SHA256withRSA";
		} else if (publicKey.getAlgorithm().equals("EC")) {
			return "SHA256withECDSA";
		}
		throw new IllegalArgumentException("Unsupported key algorithm: " + publicKey.getAlgorithm());
	}

	private static void addSecureExtensions(X509v3CertificateBuilder certBuilder, PublicKey publicKey) throws Exception {
		// Subject Alternative Names
		GeneralName[] sanArray = {
				new GeneralName(GeneralName.dNSName, "localhost"),
				new GeneralName(GeneralName.dNSName, "*.localhost"),
				new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
				new GeneralName(GeneralName.iPAddress, "::1")
		};
		GeneralNames san = new GeneralNames(sanArray);
		certBuilder.addExtension(Extension.subjectAlternativeName, false, san);

		// Enhanced Key Usage
		KeyUsage keyUsage = new KeyUsage(
				KeyUsage.digitalSignature |
						KeyUsage.keyEncipherment |
						KeyUsage.nonRepudiation |
						KeyUsage.keyAgreement
		);
		certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

		// Extended Key Usage
		ExtendedKeyUsage extKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[]{
				KeyPurposeId.id_kp_serverAuth,
				KeyPurposeId.id_kp_clientAuth,
				KeyPurposeId.id_kp_codeSigning
		});
		certBuilder.addExtension(Extension.extendedKeyUsage, false, extKeyUsage);

		// Basic Constraints
		BasicConstraints basicConstraints = new BasicConstraints(false);
		certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

		// Subject Key Identifier
		SubjectKeyIdentifier subjectKeyId = createSubjectKeyIdentifier(publicKey);
		certBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);

		// Authority Key Identifier
		AuthorityKeyIdentifier authorityKeyId = new AuthorityKeyIdentifier(
				subjectKeyId.getKeyIdentifier());
		certBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

		// Certificate Policies
		PolicyInformation[] policies = {
				new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.1"))
		};
		CertificatePolicies certificatePolicies = new CertificatePolicies(policies);
		certBuilder.addExtension(Extension.certificatePolicies, false, certificatePolicies);
	}

	private static SubjectKeyIdentifier createSubjectKeyIdentifier(PublicKey publicKey) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] keyBytes = publicKey.getEncoded();
		byte[] keyId = digest.digest(keyBytes);
		return new SubjectKeyIdentifier(keyId);
	}

	private static void saveToKeystore(String path, String password,
									   PrivateKey privateKey, X509Certificate cert) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);
		keyStore.setKeyEntry(KEYSTORE_ALIAS, privateKey, password.toCharArray(),
				new java.security.cert.Certificate[]{cert});

		try (FileOutputStream fos = new FileOutputStream(path)) {
			keyStore.store(fos, password.toCharArray());
		}
	}
}
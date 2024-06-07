/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.gematik.epa4all.tls;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import jakarta.xml.bind.Unmarshaller;

import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import lombok.NonNull;
import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

public class TSLExample {

	private static KeyStore tslTrustStore = null;
	private static InputStream tslStream = null;
	private static Document tslDocument = null;

	public static void main(String[] args) {
		try {
			// Initialize TSL-TrustStore
			TLSExample12.bouncyCastleSetup();			
			TSLExample.initializeTSLList();
			
			X509Certificate x509eeCert = null;
			final CertificateFactory fact = CertificateFactory.getInstance("X.509");
			x509eeCert = (X509Certificate) fact.generateCertificate(TSLExample.class.getClassLoader().getResourceAsStream("TSL/TSL_Signer_12_TEST-ONLY.crt"));

			String url = getOCSPUrlFromTSL(x509eeCert);
			if (url != null && !url.isEmpty()) {
				// Url found!
				System.out.println("Url found: " + url);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	public static void initializeTSLList() {
		try {
			KeystoreInfo ksInfo = new KeystoreInfo(
					TLSExample12.class.getClassLoader().getResource("TSL/tslTrustStore.jks").getFile(), "00", "PKCS12",
					"gem.tsl-ca28 test-only (gem.rca4 test-only)");

			tslTrustStore = TLSExample12.initializeKeyStore(ksInfo.ksPath, ksInfo.ksPassWd, ksInfo.ksType);
			tslStream = TSLExample.class.getClassLoader().getResourceAsStream("TSL/ECC_TU_TSL_10503.xml");
			tslDocument = createTSLDocument(tslStream);
			
		} catch( Exception ex) {
			ex.printStackTrace();
		}
	}

	public static String getOCSPUrlFromTSL(X509Certificate x509EeCert) {
		String strOcspUrl = "";
		try {
			// Check TSl Signature
			if (!checkTSLSignature(tslDocument, tslTrustStore)) {
				return "";
			}

			TrustStatusListType tslUnsigned = getTslUnsigned(tslDocument);
			List<TspService> vecTspList = tslUnsigned.getTrustServiceProviderList().getTrustServiceProvider().stream()
					.flatMap(f -> f.getTSPServices().getTSPService().stream()).map(TspService::new).toList();

			for (final TspService tspService : vecTspList) {
				strOcspUrl = checkDigitalIDentity(tspService, x509EeCert);
				if (!strOcspUrl.isEmpty()) {
					break;
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return strOcspUrl;
	}
	
	private static String checkDigitalIDentity(TspService tspService, X509Certificate x509EeCert) {
		String strOcspUrl = "";
		try {
			for (final DigitalIdentityType dit : tspService.getTspServiceType().getServiceInformation()
					.getServiceDigitalIdentity().getDigitalId()) {

				X509Certificate x509IssuerCert = null;
				final CertificateFactory fact = CertificateFactory.getInstance("X.509");
				if (dit.getX509Certificate() == null) {
					continue;
				}

				try (final ByteArrayInputStream inStream = new ByteArrayInputStream(dit.getX509Certificate())) {
					x509IssuerCert = (X509Certificate) fact.generateCertificate(inStream);
				}

				if (x509EeCert.getIssuerX500Principal().equals(x509IssuerCert.getSubjectX500Principal())) {
					if (TspService.verifyAkiMatchesSki(x509EeCert, x509IssuerCert)) {
						strOcspUrl = tspService.getTspServiceType().getServiceInformation()
								.getServiceSupplyPoints().getServiceSupplyPoint().get(0).getValue();
						break;
					}
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return strOcspUrl;
	}

	private static TrustStatusListType getTslUnsigned(@NonNull final Document tslDoc) {
		try {
			final JAXBContext jaxbContext = JAXBContext.newInstance(TrustStatusListType.class);
			final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
			final Node node = tslDoc.getFirstChild();
			final JAXBElement<TrustStatusListType> jaxbElement = unmarshaller.unmarshal(node,
					TrustStatusListType.class);

			return jaxbElement.getValue();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public static Document createTSLDocument(InputStream tslStream)
			throws ParserConfigurationException, SAXException, IOException {
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		dbf.setNamespaceAware(true); // very important
		DocumentBuilder builder = dbf.newDocumentBuilder();
		return builder.parse(tslStream);
	}

	public static boolean checkTSLSignature(@NonNull final Document tsl, @NonNull final KeyStore trustAnchor) {
		try {
			final Optional<XAdESVerificationResult> xvr = getTSLVerificationResult(tsl, trustAnchor);
			if (xvr.isEmpty()) {
				return false;
			}

			return xvr.get().getXmlSignature().checkSignatureValue(xvr.get().getValidationCertificate());
		} catch (final XAdES4jException | NoSuchAlgorithmException | XMLSignatureException | NoSuchProviderException
				| CertificateException | KeyStoreException e) {
			e.printStackTrace();
			return false;
		} catch (final IOException ex) {
			ex.printStackTrace();
			return false;
		}
	}

	private static Optional<XAdESVerificationResult> getTSLVerificationResult(final Document tsl,
			final KeyStore trustAnchor) throws XAdES4jException, NoSuchAlgorithmException, NoSuchProviderException,
			CertificateException, KeyStoreException, IOException {
		final CertificateValidationProvider certValidator = PKIXCertificateValidationProvider.builder(trustAnchor)
				.certPathBuilderProvider(BouncyCastleProvider.PROVIDER_NAME).checkRevocation(false).build();
		final XadesVerificationProfile profile = new XadesVerificationProfile(certValidator);
		final XadesVerifier verifier = profile.newVerifier();
		final Element signature = (Element) tsl.getElementsByTagNameNS(XMLNS, "Signature").item(0);
		if (signature == null) {
			return Optional.empty();
		}
		return Optional.of(verifier.verify(signature, null));
	}
}

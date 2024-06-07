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

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Spliterators;
import java.util.stream.StreamSupport;

import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;

public class OwnTrustManager implements X509TrustManager {
	
	public static final String admissionId = "1.3.36.8.3.3";
	public static final String epadvwoid = "1.2.276.0.76.4.206"; // [gemSpec_OID#GS-A_4446-11, oid_epa_dvw]

	private KeyStore privKeystore = null;
	private boolean bCheckOCSP = false;
	private boolean bCheckAdmission = false;

	public OwnTrustManager(KeyStore store, boolean bOCSP, boolean bAdmission) {
		super();
		privKeystore = store;
		this.bCheckOCSP = bOCSP;
		this.bCheckAdmission = bAdmission;
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		System.out.println(new String(chain[0].getSubjectX500Principal().getName()));
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		System.out.println("Server Certificate:");
		System.out.println(chain[0].toString());
		if (this.bCheckAdmission) {
			String[] ids = extractAdmissionId(chain[0]);
			if (!ids[1].equals(epadvwoid)) { // [gemSpec_OID#GS-A_4446-*]
				throw new CertificateException("This Certificate is not an C.FD.TLS-S (oid_epa_dvw)!");
			}
		}
		
		if (this.bCheckOCSP) {
			String ocspUrl = TSLExample.getOCSPUrlFromTSL(chain[0]);
			if (!ocspUrl.isEmpty()) {
				OCSPExample.checkCertificate(chain, ocspUrl);
			}
		}
	}

	/**
	 * Extract Extension "admission" from X509-Server-Certificate
	 * 
	 * @param certificate: valid X509-Certificate from TLS-Server
	 * @return
	 */
	private String[] extractAdmissionId(X509Certificate certificate) throws CertificateException {
		String[] vecIDs = new String[2];
		try {
			final var parsedValue = org.bouncycastle.asn1.x509.Certificate.getInstance(certificate.getEncoded())
					.getTBSCertificate().getExtensions().getExtension(new ASN1ObjectIdentifier(admissionId))
					.getParsedValue();

			// Expected value: certificate profil "C.FD.TLS-S"
			var a = (DLSequence) parsedValue;

			// [0] -> ProfessionItem [gemSpec_OID#GS-A_4446-*], "ePA Dokumentenverwaltung"
			vecIDs[0] = StreamSupport.stream(Spliterators.spliteratorUnknownSize(a.iterator(), 0), false)
					.filter(next ->  next instanceof DLSequence).findAny().filter(o -> o instanceof DLSequence)
								.map(b -> ((DLSequence) b).getObjectAt(0)).filter(o -> o instanceof DLSequence)
								.map(c -> ((DLSequence) c).getObjectAt(0)).filter(o -> o instanceof DLSequence)
								.map(d -> ((DLSequence) d).getObjectAt(0)).filter(o -> o instanceof DLSequence)
								.map(d -> ((DLSequence) d).getObjectAt(0)).filter(o -> o instanceof DLSequence)
								.map(e -> ((DLSequence) e).getObjectAt(0)).filter(o -> o instanceof DERUTF8String)
								.map(s -> ((DERUTF8String) s).getString()).orElse(null);

			// [1] -> ProfessionOID [gemSpec_OID#GS-A_4446-*], "1.2.276.0.76.4.206"
			vecIDs[1] = StreamSupport.stream(Spliterators.spliteratorUnknownSize(a.iterator(), 0), false)
					.filter(next ->  next instanceof DLSequence).findAny().filter(o -> o instanceof DLSequence)
								.map(b -> ((DLSequence) b).getObjectAt(0)).filter(o -> o instanceof DLSequence)
								.map(c -> ((DLSequence) c).getObjectAt(0)).filter(o -> o instanceof DLSequence)
								.map(d -> ((DLSequence) d).getObjectAt(0)).filter(o -> o instanceof DLSequence)
								.map(d -> ((DLSequence) d).getObjectAt(1)).filter(o -> o instanceof DLSequence)
								.map(e -> ((DLSequence) e).getObjectAt(0)).filter(o -> o instanceof ASN1ObjectIdentifier)
								.map(s -> ((ASN1ObjectIdentifier) s).toString()).orElse(null);
			return vecIDs;
		} catch (Exception ex) {
			throw new CertificateException(
					"Could not parse admissionId from Certificate. Expected certificate profile \"C.FD.TLS-S\""
							+ ex.getMessage() + "!");
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		try {
			String alias = privKeystore.aliases().nextElement();
			Certificate cert = privKeystore.getCertificate(alias);
			X509Certificate[] certs = new X509Certificate[1];
			certs[0] = (X509Certificate) cert;
			return certs;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
}

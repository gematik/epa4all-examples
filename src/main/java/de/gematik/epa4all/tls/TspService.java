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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.BiFunction;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/** Class to encapsulate package eu.europa.esig */
@SuppressWarnings("ClassCanBeRecord")
@RequiredArgsConstructor
@Getter
public class TspService {

	private final TSPServiceType tspServiceType;

	@Override
	public String toString() {
		return tspServiceType.getServiceInformation().getServiceName().getName().get(0).getValue();
	}

	/**
	 * Verify AKI (authority key identifier - an X.509 v3 certificate extension -
	 * derived from the public key of the given issuer certificate) must match with
	 * SKI (subject key identifier - an X.509 v3 certificate extension - derived
	 * from the public key of the given end-entity certificate).
	 *
	 * @param x509EeCert     end-entity certificate
	 * @param x509IssuerCert issuer certificate determined from TSL file
	 * @return true when aki matches ski otherwise false
	 */
	public static boolean verifyAkiMatchesSki(final X509Certificate x509EeCert, final X509Certificate x509IssuerCert)
			throws Exception {

		final BiFunction<X509Certificate, ASN1ObjectIdentifier, Optional<ASN1OctetString>> getAsOctet = (cert,
				identifier) -> {
			final byte[] keyIdentifier = cert.getExtensionValue(identifier.getId());
			return Optional.ofNullable(ASN1OctetString.getInstance(keyIdentifier));
		};

		final Optional<ASN1OctetString> skiAsOctet = getAsOctet.apply(x509IssuerCert, Extension.subjectKeyIdentifier);

		if (skiAsOctet.isEmpty()) {
			throw new Exception("Extension SUBJECT_KEY_IDENTIFIER_OID: " + Extension.subjectKeyIdentifier.getId()
					+ " konnte in " + x509IssuerCert.getSubjectX500Principal() + " nicht gefunden werden.");
		}
		final SubjectKeyIdentifier subKeyIdentifier = SubjectKeyIdentifier.getInstance(skiAsOctet.get().getOctets());

		final Optional<ASN1OctetString> akiAsOctet = getAsOctet.apply(x509EeCert, Extension.authorityKeyIdentifier);

		if (akiAsOctet.isEmpty()) {
			throw new Exception("Extension SUBJECT_KEY_IDENTIFIER_OID: " + Extension.authorityKeyIdentifier.getId()
					+ " konnte in " + x509EeCert.getSubjectX500Principal() + " nicht gefunden werden.");
		}

		final ASN1Primitive akiSequenceAsOctet;
		try {
			akiSequenceAsOctet = ASN1Primitive.fromByteArray(akiAsOctet.get().getOctets());
		} catch (final IOException e) {
			throw new Exception("Octets des AUTHORITY_KEY_IDENTIFIER konnten in " + x509EeCert.getSubjectX500Principal()
					+ " nicht gefunden werden.");
		}
		final AuthorityKeyIdentifier authKeyIdentifier = AuthorityKeyIdentifier.getInstance(akiSequenceAsOctet);
		return Arrays.equals(subKeyIdentifier.getKeyIdentifier(), authKeyIdentifier.getKeyIdentifier());
	}
}

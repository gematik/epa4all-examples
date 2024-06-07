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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.io.IOException;

import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.io.File;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.*;
import io.netty.util.CharsetUtil;
import java.net.Proxy;

public class OCSPExample {

	private static CertificateID g_CertID = null;
	private static final ASN1ObjectIdentifier OCSP_RESPONDER_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1")
			.intern();

	public static void main(String[] args) {
		try {
			// Initialize TLS-Session
			TLSExample12.bouncyCastleSetup();

			// Load Test certificates to check there ocsp status
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
			X509Certificate[] pathCerts = new X509Certificate[] {
					(X509Certificate) certificateFactory.generateCertificate(
							OCSPExample.class.getClassLoader().getResourceAsStream("client/www.google.de.crt")),
					(X509Certificate) certificateFactory.generateCertificate(
							OCSPExample.class.getClassLoader().getResourceAsStream("client/www.googleCA.de.crt")) };

			String ocspUrl = getOCSPUrl(pathCerts[0]);
			checkCertificate(pathCerts, ocspUrl);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static void checkCertificate(X509Certificate[] pathCerts, String ocspUrl) throws CertificateException {
		OCSPReq ocspRequest = generateOCSPRequest(pathCerts);
		OCSPResp ocspResponse = sendOCSPRequest(ocspRequest, ocspUrl);
		checkOCSPResponse(ocspResponse, pathCerts);
	}

	private static String getOCSPUrl(X509Certificate cert) {
		try {
			final var parsedValue = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded())
					.getTBSCertificate().getExtensions()
					.getExtension(new ASN1ObjectIdentifier(Extension.authorityInfoAccess.getId())).getParsedValue();

			DLSequence aiaSequence = (DLSequence) parsedValue;
			DLTaggedObject taggedObject = findObject(aiaSequence, OCSP_RESPONDER_OID, DLTaggedObject.class);
			if (taggedObject == null) {
				return null;
			}

			if (taggedObject.getTagNo() != BERTags.OBJECT_IDENTIFIER) {
				return null;
			}

			byte[] encoded = taggedObject.getEncoded();
			int length = encoded[1] & 0xFF;
			String uri = new String(encoded, 2, length, CharsetUtil.UTF_8);
			return uri;
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return "";
	}

	private static OCSPReq generateOCSPRequest(X509Certificate[] pathCerts) {
		try {
			X509CertificateHolder certHolder = new X509CertificateHolder(pathCerts[1].getEncoded());
			DigestCalculatorProvider digCalcProv;

			digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build();
			OCSPReqBuilder gen = new OCSPReqBuilder();
			g_CertID = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), certHolder,
					pathCerts[0].getSerialNumber());
			gen.addRequest(g_CertID);
			return gen.build();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	private static OCSPResp sendOCSPRequest(OCSPReq request, String url) {
		URL ocpsUrl;
		InputStream in = null;
		OutputStream out = null;

		try {
			Proxy webProxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("192.168.110.10", 3128));

			ocpsUrl = new URL(url);
			HttpURLConnection con = (HttpURLConnection) ocpsUrl.openConnection();
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-type", "application/ocsp-request");
			con.setRequestProperty("Accept", "application/ocsp-response");

			byte[] bytes = request.getEncoded();
			FileUtils.writeByteArrayToFile(new File("D:/ocsprequest.bin"), bytes);
			con.setRequestProperty("Content-length", String.valueOf(bytes.length));
			out = con.getOutputStream();
			out.write(bytes);
			out.flush();

			// Check the response
			if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
				// Log.debug("OCSPChecker: Received HTTP error: " + con.getResponseCode() + " -
				// " + con.getResponseMessage());
			}
			in = con.getInputStream();
			return new OCSPResp(in);
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException ioe) {

				}
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException ioe) {

				}
			}
		}
		return null;
	}

	private static boolean checkOCSPResponse(OCSPResp ocspResponse, X509Certificate[] pathCerts)
			throws CertificateException {
		try {
			boolean foundResponse = false;
			BasicOCSPResp brep = (BasicOCSPResp) ocspResponse.getResponseObject();
			if (brep != null) {
				if (brep != null && !brep.isSignatureValid(
						new JcaContentVerifierProviderBuilder().setProvider("BC").build(pathCerts[1].getPublicKey()))) {
					return false;
				}

				SingleResp[] singleResp = brep.getResponses();
				for (SingleResp resp : singleResp) {
					CertificateID respCertID = resp.getCertID();
					if (respCertID.equals(g_CertID)) {
						Object status = resp.getCertStatus();
						if (status == CertificateStatus.GOOD) {
							foundResponse = true;
							break;
						} else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
							throw new CertificateException(
									"Status of certificate (with serial number \" + serialNumber.toString() + \") is: revoked");
						} else if (status instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
							throw new CertificateException(
									"Status of certificate (with serial number \" + serialNumber.toString() + \") is: unknown");
						} else {
							throw new CertificateException(
									"Status of certificate (with serial number \" + serialNumber.toString() + \") is: not recognized");
						}
					}
				}
			} else {
				OCSPResponse resp = ocspResponse.toASN1Structure();
				OCSPResponseStatus status = resp.getResponseStatus();
				if (status.getIntValue() != OCSPResponseStatus.SUCCESSFUL) {
					foundResponse = false;
				}
			}
			return foundResponse;
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return false;
	}

	private static <T> T findObject(DLSequence sequence, ASN1ObjectIdentifier oid, Class<T> type) {
		for (ASN1Encodable element : sequence) {
			if (!(element instanceof DLSequence)) {
				continue;
			}

			DLSequence subSequence = (DLSequence) element;
			if (subSequence.size() != 2) {
				continue;
			}

			ASN1Encodable key = subSequence.getObjectAt(0);
			ASN1Encodable value = subSequence.getObjectAt(1);

			if (key.equals(oid) && type.isInstance(value)) {
				return type.cast(value);
			}
		}

		return null;
	}
}

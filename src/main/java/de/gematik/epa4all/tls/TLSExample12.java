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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.UUID;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.*;

public class TLSExample12 {
	
	public static final String urlServer = "https://127.0.0.1:8443";

	// [gemSpec_Krypt#A_15751-02, ePA-spezifische TLS-Vorgaben]
	public static final String[] vecCiphers = new String[] {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"};

	// [gemSpec_Krypt#GS-A_4385, gemSpec_Krypt#A_18467]
	public static final String[] vecProtocols = new String[] { "TLSv1.2" };

	public static SSLContext g_sslContext = null;
	public static HttpClient g_HttpClient = null;	

	public static void createTLSSession(String urlServer, KeystoreInfo ksInfo, KeystoreInfo tsInfo) {
		KeyStore ksStore = null;
		KeyStore tsStore = null;

		try {
			g_sslContext = SSLContext.getInstance(vecProtocols[0], "BCJSSE"); // [gemSpec_Krypt#GS-A_4385]

			ksStore = initializeKeyStore(ksInfo.ksPath, ksInfo.ksPassWd, ksInfo.ksType);
			tsStore = initializeKeyStore(tsInfo.ksPath, tsInfo.ksPassWd, tsInfo.ksType);

			KeyManagerFactory keyMgrFactory = initializeKeyManager(ksStore, ksInfo.ksPassWd);
			TrustManagerFactory trustManagers = initializeTrustManager(tsStore, tsInfo.ksPassWd);

			final TrustManager[] tms = trustManagers.getTrustManagers();
			if (tms.length > 0) {
				tms[0] = new OwnTrustManager(tsStore, false, false);
			}
			g_sslContext.init(keyMgrFactory.getKeyManagers(), tms, null);

			// Ciphersuits setzen
			// [gemSpec_Krypt#A_15751-02, ePA-spezifische TLS-Vorgaben]
			SSLParameters params = g_sslContext.getDefaultSSLParameters();
			params.setCipherSuites(vecCiphers);
			params.setProtocols(new String[] {vecProtocols[0]});
			params.setNeedClientAuth(true);
			params.setWantClientAuth(true);

			final var builder = HttpClient.newBuilder();
			builder.sslParameters(params);
			builder.sslContext(g_sslContext);
			builder.sslParameters(params);
			builder.version(HttpClient.Version.HTTP_2);
			builder.followRedirects(HttpClient.Redirect.ALWAYS);
			builder.connectTimeout(Duration.ofSeconds(1000));

			g_HttpClient = builder.build();

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	public static HttpResponse<byte[]> sendMessage(String url, String uuid, String mimetype) {
		HttpRequest httpReq = createHttpMessage(url, uuid, null, "GET", mimetype);
		try {
			return g_HttpClient.send(httpReq, HttpResponse.BodyHandlers.ofByteArray());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static HttpResponse<byte[]> sendMessage(String url, String uuid, byte[] pMessage, String mimetype) {
		HttpRequest httpReq = createHttpMessage(url, uuid, pMessage, "POST", mimetype);
		try {
			return g_HttpClient.send(httpReq, HttpResponse.BodyHandlers.ofByteArray());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args) {
		KeystoreInfo ksInfo = new KeystoreInfo(
				TLSExample12.class.getClassLoader().getResource("client/clientks.jks").getFile(), "00", "PKCS12", "testclient101");

		KeystoreInfo tsInfo = new KeystoreInfo(
				TLSExample12.class.getClassLoader().getResource("client/clientts.jks").getFile(), "00", "PKCS12", "testserver 101");

		try {
			bouncyCastleSetup();
			TSLExample.initializeTSLList();
			createTLSSession(urlServer, ksInfo, tsInfo);
			
			// Get Consent Decision to check TLS-Connection
			HttpResponse<byte[]> response = sendMessage(urlServer + "/information/api/v1/ehr/Z123456789/consentdecisions", UUID.randomUUID().toString(),"application/json");

			handleResponse(response.statusCode());
			System.out.println(new String(response.body()));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static boolean handleResponse(int iCode) {
		if (iCode == 200) {
			return true;
		} else {
			if (iCode == 400) {
				System.out.println("Bad Request (malformedRequest)");
			} else if (iCode == 404) {
				System.out.println("Not found Request (noHealthRecord)");
			} else if (iCode == 409) {
				System.out.println("Conflict (statusMismatch)");
			} else if (iCode == 500) {
				System.out.println("Internal Server Error (internalError)");
			} else {
				System.out.println("Unknown Error: " + iCode);
			}
			return false;
		}
	}

	/**
	 * This function create the Message to call "getConsentDecisionInformation"
	 * 
	 * @return
	 */
	public static HttpRequest createHttpMessage(String url, String uuid, byte[] pData, String messagetype, String mimetype) {
		HttpRequest request = null;
		
		if (messagetype.equals("GET")) {
			request = HttpRequest.newBuilder().uri(URI.create(url))
					.GET().header("uuid", uuid)
					.header("Content-type", mimetype)
					.header("x-useragent","CLIENTID1234567890AB/2.1.12-45").build();
		} else {
			request = HttpRequest.newBuilder().uri(URI.create(url))
					.POST(HttpRequest.BodyPublishers.ofByteArray(pData)).header("uuid", uuid)
					.header("Content-type", mimetype).build();
		}
		
		return request;
	}

	public static KeyStore initializeKeyStore(final String path, final String pass, final String type)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		InputStream keyStoreIs = new FileInputStream(new File(path));
		KeyStore ksJks = KeyStore.getInstance(type);
		ksJks.load(keyStoreIs, pass.toCharArray());
		keyStoreIs.close();
		return ksJks;
	}

	public static KeyManagerFactory initializeKeyManager(final KeyStore store, final String password)
			throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException {
		KeyManagerFactory kmf = null;
		kmf = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
		kmf.init(store, password.toCharArray());
		return kmf;
	}

	public static TrustManagerFactory initializeTrustManager(final KeyStore store, final String password)
			throws KeyStoreException, NoSuchAlgorithmException {
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(store);
		return trustManagerFactory;
	}

	public static void bouncyCastleSetup() {
		// [gemSpec_Krypt#3.15.3 ePA-spezifische TLS-Vorgaben]
		Security.setProperty("jdk.tls.namedGroups", "secp256r1,secp384r1,brainpoolP256r1,brainpoolP384r1,brainpoolP512r1");
		System.setProperty("jdk.tls.namedGroups", "secp256r1,secp384r1,brainpoolP256r1,brainpoolP384r1,brainpoolP512r1");
		System.setProperty("jdk.tls.ephemeralDHKeySize", "2048");
		System.setProperty("java.util.logging ", "FINEST");

		Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

		// Ausgabe der Security Providers -> prüfe, ob Bouncycastle an oberster Stelle stehen
		for (Provider prov : Security.getProviders()) {
			System.out.println("Name:" + prov.getName());
		}
	}
}

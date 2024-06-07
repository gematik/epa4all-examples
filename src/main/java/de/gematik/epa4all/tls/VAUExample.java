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

import java.net.http.HttpResponse;
import java.util.UUID;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import de.gematik.vau.lib.VauClientStateMachine;

public class VAUExample {
	public static final String vauurl = "/VAU";
	public static final String vaucid = "VAU-CID";
	
	public static VauClientStateMachine g_vauClient = null;
	
	public static void main(String[] args) {
		HttpResponse<byte[]> response = null;
		
		KeystoreInfo ksInfo = new KeystoreInfo(
				TLSExample12.class.getClassLoader().getResource("client/clientks.jks").getFile(), 
				"00", 
				"PKCS12", 
				"testclient101");

		KeystoreInfo tsInfo = new KeystoreInfo(
				TLSExample12.class.getClassLoader().getResource("client/clientts.jks").getFile(), 
				"00", 
				"PKCS12", 
				"testserver 101");
		
		// Initialize TLS-Session
		TLSExample12.bouncyCastleSetup();
		TLSExample12.createTLSSession(TLSExample12.urlServer, ksInfo, tsInfo);
		
		// Create VAU-Channel
		String uuid = UUID.randomUUID().toString();
		VAUExample.createVAUChannel(uuid);
		
		// Send a test message to test encryption and decryption
		response = TLSExample12.sendMessage(TLSExample12.urlServer + "/epa/vzd/v1/vzdToken", uuid, encryptData("Hello Server".getBytes()), "application/cbor");
		
		if (!TLSExample12.handleResponse(response.statusCode())) {
			return;
		}
		
		// Expected Value: "Hello Client"
		System.out.println(new String(decryptData(response.body())));
	}
	
	public static byte[] encryptData(byte[] pData) {
		byte[] encryptedClientVauMessage = g_vauClient.encryptVauMessage(pData);
		return encryptedClientVauMessage;
	}
	
	public static byte[] decryptData(byte[] encryptedData) {
		byte[] pData = g_vauClient.decryptVauMessage(encryptedData);
		return pData;
	}
	
	/**
	 * [gemSpec_Krypt#7.1 Verbindungsaufbau/Schlüsselaushandlung]
	 * @param uuid -> bind session on unique uuid
	 */
	public static void createVAUChannel(String uuid) {
		try {
			g_vauClient = new VauClientStateMachine();
			
			// Generate Keypair and send public Keys to Server (Nachricht 1)
            byte[] message1 = g_vauClient.generateMessage1();
            handleMessage(message1);
			HttpResponse<byte[]> response = TLSExample12.sendMessage( TLSExample12.urlServer + vauurl,
																	uuid,
																	message1, "application/cbor");
			
			if (!TLSExample12.handleResponse(response.statusCode())) {
				return;
			}
			
			// [gemSpec_Krypt#A_24608 - VAU-Protokoll: VAU-Instanz: Nachricht 2]
			// Header must contain VAU-CID
			List<String> vaucids = response.headers().allValues(vaucid);
			if (vaucids == null || vaucids.size() == 0) {
				return;
			}
			
			// Receive KEM-CHiffre and encrypted VAU key (Nachricht 2)
			// Generate and encrypt hash value (Nachricht 3)
			handleMessage(response.body());
			byte[] message3Encoded = g_vauClient.receiveMessage2(response.body());
			
			handleMessage(message3Encoded);
			response = TLSExample12.sendMessage(TLSExample12.urlServer + vaucids.get(0), // VAU-CID is part of Url
												uuid,
												message3Encoded, "application/cbor");
			
			if (!TLSExample12.handleResponse(response.statusCode())) {
				return;
			}
			
			// Receive encrypted hash valuer from Server and finish (Nachricht 4)
			handleMessage(response.body());
			g_vauClient.receiveMessage4(response.body());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	/**
	 * This function demonstrate, how to get the parts of message content
	 * @param messageEncoded
	 */
	public static void handleMessage(byte[] messageEncoded) {
		try {
			JsonNode messageTree = new CBORMapper().readTree(messageEncoded);
			if (messageTree == null) {
				return;
			}
			
			// Extract values...
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}

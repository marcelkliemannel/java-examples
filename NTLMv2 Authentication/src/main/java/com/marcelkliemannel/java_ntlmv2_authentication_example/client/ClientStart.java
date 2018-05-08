package com.marcelkliemannel.java_ntlmv2_authentication_example.client;


import org.eclipse.jetty.client.HttpClient;

/**
 * Minimal client instance to make a NTLMv2 authentication request.
 */
public class ClientStart {
    // ---- Class Variables
    // ---- Instance Variables
    // ---- Constructors
    // ---- Public Methods

    public static void main(String[] args) throws Exception {
        HttpClient httpClient = null;
        try {
            httpClient = new HttpClient();
            httpClient.start();

            NTLMv2ClientSideHandler ntlMv2ClientSideHandler = new NTLMv2ClientSideHandler(httpClient);
            ntlMv2ClientSideHandler.authenticate();
        }
        finally {
            if (httpClient != null) {
                httpClient.stop();
            }
        }
    }

    // ---- Package/Protected Methods
    // ---- Private Methods
    // ---- Inner Class
}

package com.marcelkliemannel.dev.java_ntlmv2_authentication_example.client;


import org.eclipse.jetty.client.HttpClient;

/**
 * Minimal client instance to make an NTLMv2 authentication request.
 *
 * @author Marcel Kliemannel &lt;dev@marcelkliemannel.com&gt;
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

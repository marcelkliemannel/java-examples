package com.marcelkliemannel.dev.java_ntlmv2_authentication_example.server;

import org.eclipse.jetty.server.Server;

/**
 * Minimal server instance for handling a NTLMv2 authentication request.
 *
 * @author Marcel Kliemannel &lt;dev@marcelkliemannel.com&gt;
 */
public class ServerStart {
    // ---- Class Variables
    // ---- Instance Variables
    // ---- Constructors
    // ---- Public Methods

    public static void main(String[] args) throws Exception {
        Server server = null;
        try {
            server = new Server(8080);
            server.setHandler(new NTLMv2ServerSideHandler());

            server.start();
            server.join();
        }
        finally {
            if (server != null) {
                server.stop();
            }
        }
    }
    
    // ---- Package/Protected Methods
    // ---- Private Methods
    // ---- Inner Class
}

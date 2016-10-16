package com.marcelkliemannel.dev.java_ntlmv2_authentication_example.server;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.ntlmv2.liferay.NtlmLogonException;
import org.ntlmv2.liferay.NtlmManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * This class handles the server side NTLMv2 authentication.
 *
 * NOTICE:
 * - This example is just for showing the workflow of the NTLMv2 authentication. Therefore
 * things like error handling, content validation or synchronisation of variables are ignored.
 *
 * - In a normal workflow the NTLMv2 massages are transported by the HTTP header fields
 * 'Authorization' (from client) or 'WWW-Authenticate' (from server) and the HTTP status
 * code '401 - Unauthorized'. Unfortunately if the 'jetty' library recognise such header
 * fields or status codes her own authentication handler jumps in but fails to parse
 * the NTLMv2 header fields. Therefore the communication in this example is done over
 * the HTTP content and status code '200 - OK'.
 *
 * @author Marcel Kliemannel &lt;dev@marcelkliemannel.com&gt;
 */
class NTLMv2ServerSideHandler extends AbstractHandler {
    // ---- Class Variables

    private static final SecureRandom secureRandom = new SecureRandom();
    private static       NtlmManager  ntlmManager;

    // ---- Instance Variables

    private final Map<String, byte[]> usernameChallenges = new HashMap<>();

    // ---- Constructors

    NTLMv2ServerSideHandler() {
        if (ntlmManager == null) {
            // Should be the same as on client side configuration
            String domain                      = "COM";
            String domainControllerHost        = "11.12.13.14";
            String domainControllerNetbiosName = "domaincontroller";
            // The 'liferay' library requires that there is an '@' and a '$' sign
            // in the service account username to determine the 'account name'
            // (everything before the '@' sign) and the 'computer name' (everything
            // before the '$' sign.
            String serviceAccountUsername      = "contentserver@com.ntlmtest$";
            String serviceAccountPassword      = "123456";
            ntlmManager = new NtlmManager(domain, domainControllerHost, domainControllerNetbiosName, serviceAccountUsername, serviceAccountPassword);
        }
    }

    // ---- Public Methods

    @Override
    public void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {
        // Better: Set HTTP status code to '401 - Unauthorized' (see notice above).
        httpServletResponse.setStatus(HttpServletResponse.SC_OK);

        String usernameHeader = request.getHeader("X-Username");

        // Better: Use the 'Authorization' HTTP header field (see notice above).
        String authorizationHeader = httpServletRequest.getReader().readLine().substring(5);
        byte[] ntlmv2Message = Base64.getDecoder().decode(authorizationHeader);

        // The entry at position 8 is the type indicator.
        switch (ntlmv2Message[8]) {
            // Handle type 1 message from client -> send type 2 message.
            case 1:
                // Generate an 8 byte random challenge for the username.
                byte[] challenge = new byte[8];
                secureRandom.nextBytes(challenge);
                usernameChallenges.put(usernameHeader, challenge);

                // Generate a type 2 message
                byte[] type2Message = ntlmManager.negotiate(ntlmv2Message, challenge);

                // Better: Use the 'WWW-Authenticate' HTTP header field (see notice above).
                // Always encode ntlmv2 messages via base64 before converting to string!
                String wwwAuthenticateHeader = "NTLM " + new String(Base64.getEncoder().encode(type2Message));
                httpServletResponse.getWriter().append(wwwAuthenticateHeader);

                request.setHandled(true);

                break;

            // Handle type 3 message from client -> send authentication result
            case 3:
                try {
                    // Communicate with the domain controller for authentication
                    ntlmManager.authenticate(ntlmv2Message, usernameChallenges.get(usernameHeader));

                    // The client has successfully authorized!

                    httpServletResponse.getWriter().append("Authenticated!");
                }
                catch (IOException | NoSuchAlgorithmException | NtlmLogonException e) {
                    httpServletResponse.getWriter().append("Authentication failed!");
                }

                request.setHandled(true);

                break;
        }
    }

    // ---- Package/Protected Methods
    // ---- Private Methods
    // ---- Inner Class
}

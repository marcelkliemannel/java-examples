package com.marcelkliemannel.dev.java_ntlmv2_authentication_example.client;

import jcifs.ntlmssp.Type1Message;
import jcifs.smb.NtlmContext;
import jcifs.smb.NtlmPasswordAuthentication;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.StringContentProvider;

import java.io.IOException;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * This class handles the client side NTLMv2 authentication.
 *
 * NOTICE:
 * - This example is just for showing the workflow of the NTLMv2 authentication. Therefore
 * things like error handling, content validation or synchronisation of variables are ignored.
 *
 * - In a normal workflow the NTLMv2 massages are transported by the HTTP header fields
 * 'Authorization' (from client) or 'WWW-Authenticate' (from server) and the HTTP status
 * code '401 - Unauthorized'. Unfortunately if the 'jetty' library recognise such header
 * fields or status codes, her own authentication handler jumps in, but fails to parse
 * the NTLMv2 header fields. Therefore the communication in this example is done over
 * the HTTP content and status code '200 - OK'.
 *
 * @author Marcel Kliemannel &lt;dev@marcelkliemannel.com&gt;
 */
class NTLMv2ClientSideHandler {
    // ---- Class Variables

    // Ip address of the example server
    private final static String SERVER      = "http://localhost:8080";
    private final static String WORKSTATION = "MyWorkstation";
    // Should be the same as on server side configuration
    private final static String DOMAIN      = "COM";
    private final static String USERNAME    = "user";
    private final static String PASSWORD    = "1234";

    // ---- Instance Variables

    private final HttpClient httpClient;

    private NtlmPasswordAuthentication ntlmPasswordAuthentication;

    // ---- Constructors

    NTLMv2ClientSideHandler(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    // ---- Public Methods
    // ---- Package/Protected Methods

    void authenticate() throws IOException, InterruptedException, ExecutionException, TimeoutException {
        // The 'ntlmContext' instance can only be used once in an authentication process:
        // If there was a type 1 message generated, you can only generate a type 2 message
        // and if a type 2 message was generated the instance cant not be used again.
        ntlmPasswordAuthentication = new NtlmPasswordAuthentication(DOMAIN, USERNAME, PASSWORD);
        NtlmContext ntlmContext = new NtlmContext(ntlmPasswordAuthentication, true);

        // Generate type 1 message.
        byte[] rawType1Message = ntlmContext.initSecContext(new byte[]{}, 0, 0);
        // This way or derive a subclass from NtlmContext and set the workstation in the constructor.
        Type1Message type1Message = new Type1Message(rawType1Message);
        type1Message.setSuppliedWorkstation(WORKSTATION);

        // Send type 1 message to server -> receive type 2 message with challenge.
        ContentResponse type2MessageContentResponse = makeServerRequest(type1Message.toByteArray());
        String respondedContent = type2MessageContentResponse.getContentAsString().substring(5); // Remove "NTLM " prefix
        byte[] type2Message = Base64.getDecoder().decode(respondedContent);

        // Generate type 3 message.
        byte[] type3Message = ntlmContext.initSecContext(type2Message, 0, 0);

        // Better: Check HTTP status code (see notice above)
        // Send type 3 message -> get authentication result from server.
        String authenticationResult = makeServerRequest(type3Message).getContentAsString();
        System.out.println(authenticationResult);
    }

    // ---- Private Methods

    private ContentResponse makeServerRequest(byte[] ntlmv2Message) throws InterruptedException, ExecutionException, TimeoutException {
        Request request = httpClient.newRequest(SERVER);

        // The server side needs the username in every NTLMv2 message
        request.header("X-Username", ntlmPasswordAuthentication.getUsername());

        // Better: Use the 'Authorization' HTTP header field (see notice above).
        // Always encode ntlmv2 messages via base64 before converting to string!
        String authorizationHeader = "NTLM " + new String(Base64.getEncoder().encode(ntlmv2Message));
        request.content(new StringContentProvider(authorizationHeader, "UTF-8"));

        return request.send();
    }

    // ---- Inner Class
}

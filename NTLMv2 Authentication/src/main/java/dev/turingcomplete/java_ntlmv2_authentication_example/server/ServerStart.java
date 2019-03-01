package dev.turingcomplete.java_ntlmv2_authentication_example.server;

import org.eclipse.jetty.server.Server;

/**
 * Minimal embedded Jetty server instance to handling a NTLMv2 authentication request.
 */
public class ServerStart {
  // -- Fields ------------------------------------------------------------------------------- //
  // -- Initialization ----------------------------------------------------------------------- //
  // -- Exposed Methods ---------------------------------------------------------------------- //

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

  // -- Private Methods ---------------------------------------------------------------------- //
  // -- Inner Type --------------------------------------------------------------------------- //
  // -- End of Class ------------------------------------------------------------------------- //
}

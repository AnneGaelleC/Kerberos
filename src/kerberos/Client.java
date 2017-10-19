package kerberos;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.misc.BASE64Encoder;
 
/**
 * <p>Le client se connecte au Key Distribution Center (KDC) en utilisant JAAS puis
 * demande un ticket pour le server, est l écrit dans le fichier<i>service-ticket.txt</i>.</p>
 */
public class Client {
 
  public static void main( String[] args) {
    try {
      //  Kerberos propriétés.
      Properties props = new Properties();
      props.load( new FileInputStream( "/Users/anne-gaelle/Documents/Brésil/S2/SAS/KerberosV2/src/kerberos/client.properties"));
      System.setProperty( "sun.security.krb5.debug", "true");
      System.setProperty( "java.security.krb5.realm", props.getProperty( "realm")); 
      System.setProperty( "java.security.krb5.kdc", props.getProperty( "kdc"));
      System.setProperty( "java.security.auth.login.config", "/Users/anne-gaelle/Documents/Brésil/S2/SAS/KerberosV2/src/kerberos/jaas.conf");
      System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
      String username = props.getProperty( "client.principal.name");
      String password = props.getProperty( "client.password");
      // Oid mechanism = use Kerberos V5 as the security mechanism.
      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
      Client client = new Client();
      // Login to the KDC.
      client.login( username, password);
      // Request the service ticket.
      client.initiateSecurityContext( props.getProperty( "service.principal.name"));
      // Write the ticket to disk for the server to read.
      encodeAndWriteTicketToDisk( client.serviceTicket, "./security.token");
      System.out.println( "Service ticket encoded to disk successfully");
    }
    catch ( LoginException e) {
      e.printStackTrace();
      System.err.println( "There was an error during the JAAS login");
      System.exit( -1);
    }
    catch ( GSSException e) {
      e.printStackTrace();
      System.err.println( "There was an error during the security context initiation");
      System.exit( -1);
    }
    catch ( IOException e) {
      e.printStackTrace();
      System.err.println( "There was an IO error");
      System.exit( -1);
    }
  }
 
  public Client() {
    super();
  }
 
  private static Oid krb5Oid;
 
  private Subject subject;
  private byte[] serviceTicket;
 
  // Authentification KDC utilidant JAAS.
  private void login( String username, String password) throws LoginException {
    LoginContext loginCtx = null;
    // "Client" référe au JAAS configuration dans le fichier jaas.conf.
    loginCtx = new LoginContext( "Client",
        new LoginCallbackHandler( username, password));
    loginCtx.login();
    this.subject = loginCtx.getSubject();
  }
 
  // Begin the initiation of a security context with the target service.
  private void initiateSecurityContext( String servicePrincipalName)
      throws GSSException {
    GSSManager manager = GSSManager.getInstance();
    GSSName serverName = manager.createName( servicePrincipalName,
        GSSName.NT_HOSTBASED_SERVICE);
    final GSSContext context = manager.createContext( serverName, krb5Oid, null,
        GSSContext.DEFAULT_LIFETIME);
    // The GSS context initiation has to be performed as a privileged action.
    this.serviceTicket = Subject.doAs( subject, new PrivilegedAction<byte[]>() {
      public byte[] run() {
        try {
          byte[] token = new byte[0];
          // This is a one pass context initialisation.
          context.requestMutualAuth( false);
          context.requestCredDeleg( false);
          return context.initSecContext( token, 0, token.length);
        }
        catch ( GSSException e) {
          e.printStackTrace();
          return null;
        }
      }
    });
 
  }
 
  // Base64 code le ticket et l ajoute au fichier.
  private static void encodeAndWriteTicketToDisk( byte[] ticket, String filepath)
      throws IOException {
    BASE64Encoder encoder = new BASE64Encoder();    
    FileWriter writer = new FileWriter( new File( filepath));
    String encodedToken = encoder.encode( ticket);
    writer.write( encodedToken);
    writer.close();
  }
}

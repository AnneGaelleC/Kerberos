package kerberos;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.misc.BASE64Decoder;
 

public class Server {
 
  public static void main( String[] args) {
    try {

      Properties props = new Properties();
      props.load( new FileInputStream( "/Users/anne-gaelle/Documents/Brésil/S2/SAS/KerberosV2/src/kerberos/server.properties"));
      System.setProperty( "sun.security.krb5.debug", "true");
      System.setProperty( "java.security.krb5.realm", props.getProperty( "realm"));
      System.setProperty( "java.security.krb5.kdc", props.getProperty( "kdc"));
      System.setProperty( "java.security.auth.login.config", "/Users/anne-gaelle/Documents/Brésil/S2/SAS/KerberosV2/src/kerberos/jaas.conf");
      System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
      String password = props.getProperty( "service.password");
      // Oid mechanism = use Kerberos V5 as the security mechanism.
      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
      Server server = new Server();
      // Login au KDC.
      server.login( password);
      byte serviceTicket[] = loadTokenFromDisk();
      // Request the service ticket.
      String clientName = server.acceptSecurityContext( serviceTicket);
      System.out.println( "\nSecurity context successfully initialised!");
      System.out.println( "\nHello World " + clientName + "!");
    }
    catch ( LoginException e) {
      e.printStackTrace();
      System.err.println( "There was an error during the JAAS login");
      System.exit( -1);
    }
    catch ( GSSException e) {
      e.printStackTrace();
      System.err.println( "There was an error during the security context acceptance");
      System.exit( -1);
    }
    catch ( IOException e) {
      e.printStackTrace();
      System.err.println( "There was an IO error");
      System.exit( -1);
    }
  }
 
  
  private static byte[] loadTokenFromDisk() throws IOException {
    BufferedReader in = new BufferedReader( new FileReader( "security.token"));
    System.out.println( new File( "security.token").getAbsolutePath());
    String str;
    StringBuffer buffer = new StringBuffer();
    while ((str = in.readLine()) != null) {
       buffer.append( str + "\n");
    }
    in.close();
    //System.out.println( buffer.toString());
    BASE64Decoder decoder = new BASE64Decoder();
    return decoder.decodeBuffer( buffer.toString());
  }
 
  private static Oid krb5Oid;
 
  private Subject subject;
 
  private void login( String password) throws LoginException {
    LoginContext loginCtx = null;
    loginCtx = new LoginContext( "Server",
        new LoginCallbackHandler( password));
    loginCtx.login();
    this.subject = loginCtx.getSubject();
  }
 
  private String acceptSecurityContext( final byte[] serviceTicket)
      throws GSSException {
    krb5Oid = new Oid( "1.2.840.113554.1.2.2");
 

    return Subject.doAs( subject, new PrivilegedAction<String>() {
      public String run() {
        try {
          // Identifie le server avec lequel les communications sont faites.
          GSSManager manager = GSSManager.getInstance();
          GSSContext context = manager.createContext( (GSSCredential) null);
          context.acceptSecContext( serviceTicket, 0, serviceTicket.length);
          return context.getSrcName().toString();
        }
        catch ( Exception e) {
          e.printStackTrace();
          return null;
        }
      }
    });
  }
}

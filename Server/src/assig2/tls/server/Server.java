package assig2.tls.server;

// General & IO
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Base64;

// TCP/TLS Functionality
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509KeyManager;

/**
 * assig2.tls.server.Server implements a TCP Server with <b>TLSv1.3.</b>
 * This assignment is being marked on the basis of a TLS implementation,  
 * so it's single-threaded for now. In real-life, it wouldn't be very useful.
 * @author Sam Milburn (300509843)
 */
public class Server {
	public static final int DEFAULTPORT		= 4444;
	private int tcpPort						= -1;
	// Everything necessary for opening a TLS socket with our certificates.
	private SSLServerSocket socket			= null;
	private KeyStore ks						= null;
	
	/**
	 * Process any incoming SSL Clients.
	 * @throws IllegalStateException if there's an issue with the Socket.
	 */
	public void processClients() throws IllegalStateException {
		if(this.socket == null || this.socket.isClosed()) {
			throw new IllegalStateException("Couldn't process clients because there is something wrong with the state of the SSLServerSocket.");
		}
		// Process clients in a simple single-threaded loop.
		boolean listen = true;
		while(listen) {
			SSLSocket client = null;
			try {
				client				= (SSLSocket) this.socket.accept();
				System.out.println("Client connected: "+client.getInetAddress());
				PrintWriter spw		= new PrintWriter(client.getOutputStream(), true);
				BufferedReader br	= new BufferedReader(new InputStreamReader(client.getInputStream()));
				// Read the input line
				String line = br.readLine();
				if(line.equals("Hello, Server!")) {
					spw.println("Hello, Client!");
				} else {
					spw.println("Hello, Stranger!");
				}
				client.close(); // Close to finish off.
			} catch(IOException ioe) {
				System.out.println("I/O issue with the client socket. Closing...");
				try {
					if(client != null) client.close();
				} catch(IOException ioe2) { /* Not much you can do in this case. */ }
			}
		}
	}
	
	/**
	 * @return a TLSv1.3 Server Socket.
	 * @throws SSLException if there's some issue initialising the precursor components to the Socket.
	 */
	private SSLServerSocket establishSocket() throws SSLException {
		SSLServerSocket s = null; SSLContext context = null;
		try {
			context = SSLContext.getInstance("TLSv1.3"); // For later.
		} catch (NoSuchAlgorithmException e) {
			throw new SSLException("Couldn't instantiate the SSLContext.");
		}
		// Get a KMF instance, load the KeyStore we established earlier.
		KeyManagerFactory kmf = null;
		X509KeyManager x509km = null;
		try {
			kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			if(this.ks == null) {
				throw new SSLException("Couldn't load the KeyStore for KeyManager initialisation.");
			}
			kmf.init(this.ks, "".toCharArray()); // Passwordless, like specified in generateKeyStore().
			for(KeyManager km: kmf.getKeyManagers()) {
				if(km instanceof X509KeyManager) {
					x509km = (X509KeyManager)km; break; // There should be one instance of the X509KeyManager.
				}
			}
		} catch (NoSuchAlgorithmException nsae) {
			throw new SSLException("Couldn't locate the KMF instance with the default algorithm.");
		} catch (UnrecoverableKeyException uke) {
			throw new SSLException("Couldn't assign keystore to KMF.");
		} catch (KeyStoreException ksee) {
			throw new SSLException("KMF initialisation failed.");
		} catch(IllegalStateException ise) {
			throw new SSLException("KMF not initialised when reading getKeyManagers().");
		}
		
		// Initialise the SSLContext so that resultant Server Sockets respect the derived KeyManager.
		SSLServerSocketFactory socketfactory = null;
		try {
			context.init(new KeyManager[] { x509km }, null, new SecureRandom());
			socketfactory = (SSLServerSocketFactory) context.getServerSocketFactory();
			
		} catch(KeyManagementException kme) {
			throw new SSLException("Couldn't initialise the SSLContext with the KeyManager array.");
		} catch(IllegalStateException ise) {
			throw new SSLException("Couldn't get the Server Socket Factory from the SSLContext.");
		}
		// Initialise and return the Server.
		try {
			s = (SSLServerSocket) socketfactory.createServerSocket(this.tcpPort);
			return s; // Yield the ServerSocket.
		} catch(IOException | SecurityException e) {
			throw new SSLException("Couldn't create the Server Socket for some networking or security reason.");
		}
	}
	
	/**
	 * @return A KeyStore associating the frontend.org private key to a PKI-chain of X509 Certificates.
	 * @throws FileNotFoundException if we can't find the files by their file path.
	 * @throws IOException if we have an issue reading the files.
	 * @throws CertificateException if we have an issue loading the certificates from file.
	 * @throws KeyStoreException if we have an issue initialising the KeyStore.
	 */
	private KeyStore generateKeyStore() 
			throws FileNotFoundException, IOException, CertificateException, KeyStoreException {
		// I'll manually load these here, though if I made a helper function 
		// to appropriately order the X509s (most signed to signers), 
		// I could load these as a list of certificate paths and a key path.
		String[] certificatePaths = new String[] {
			"Certificates/frontend.org.pem", "Certificates/milbursamuRA.com.pem"
			}; 
		String keyPath = "Keys/frontend.org.key"; // PKCS8 PEM format.
		File frontendCertF		= new File(certificatePaths[0]);
		File rootCertF			= new File(certificatePaths[1]);
		File frontendKeyF		= new File(keyPath);
		// Just check they're extant.
		File[] files = new File[] {frontendCertF, rootCertF, frontendKeyF}; 
		for(File f: files) {
			if(!f.exists() || !f.isFile() || !f.canRead()) {
				throw new FileNotFoundException("Couldn't read a certificate or key file.");
			}
		}
		// Start loading them.
		CertificateFactory cf; 
		X509Certificate frontendCert; X509Certificate rootCert; String frontendKeyS;
		try {
			cf = CertificateFactory.getInstance("X.509");
			// Generate and assign the frontend cert.
			FileInputStream FIS = new FileInputStream(frontendCertF);
			frontendCert = (X509Certificate) cf.generateCertificate(FIS);
			FIS.close();
			
			// Generate and assign the root cert.
			FIS = new FileInputStream(rootCertF);
			rootCert = (X509Certificate) cf.generateCertificate(FIS);
			FIS.close();
			
			// Read the key (raw).
			FIS = new FileInputStream(frontendKeyF);
			frontendKeyS = new String(FIS.readAllBytes());
			FIS.close();
		} catch(CertificateException ce) {
			throw new CertificateException("Couldn't initialise the certificate factory or certificates.");
		} catch(IOException ioe) {
			throw new IOException("Couldn't read/write files during certificate generation.");
		}
		
		// Certificate Chain.
		X509Certificate[] chain = new X509Certificate[] { frontendCert, rootCert };
		
		// KeyStore: associate a private key with a certificate chain.
		KeyStore keyWithChain = null;
		try {
			keyWithChain = KeyStore.getInstance(KeyStore.getDefaultType());
			keyWithChain.load(null, null);
			
			// Clean the file of non-key information, base-64 decode.
			byte[] privateKey; 
			frontendKeyS = 
				frontendKeyS.replace("-----BEGIN PRIVATE KEY-----", "")
							.replace("-----END PRIVATE KEY-----", "")
							.replaceAll("\n", "")
							.replaceAll("\r\n", ""); ;
			privateKey = Base64.getDecoder().decode(frontendKeyS);
			// Turn in to a KeySpec, feed it to the KeyFactory. 
			PKCS8EncodedKeySpec keyspec		= new PKCS8EncodedKeySpec(privateKey);
			KeyFactory kf					= KeyFactory.getInstance("RSA");
			RSAPrivateKey rsapk				= (RSAPrivateKey) kf.generatePrivate(keyspec);
			// Set the KeyStore for the Socket Context.
			keyWithChain.setKeyEntry("frontend.org", rsapk, "".toCharArray(), chain);
			return keyWithChain;
		} catch (KeyStoreException e) {
			throw new KeyStoreException("Couldn't initialise the KeyStore.");
		} catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException("Couldn't locate the algorithm for KeyStore load().");
		} catch (InvalidKeySpecException e) {
			throw new KeyStoreException("Couldn't generate the RSA private key for the KeyStore.");
		}
	}
	
	/**
	 * @param tcpPort a tcp port between 1 and 49150.
	 * @throws IllegalArgumentException if the argument is invalid.
	 */
	public Server(int tcpPort) throws IllegalArgumentException {
		if(tcpPort <= 1 || tcpPort >= 49151) {
			throw new IllegalArgumentException("Port number in an invalid range.");
		}
		this.tcpPort = tcpPort;
		try {
			this.ks			= this.generateKeyStore(); // Read keys and certificates from their files.
			this.socket		= this.establishSocket(); // Establish the Socket from the KeyStore.
			//this.establishSocket();
			
		} catch (IOException ioe) {
			System.out.println("Error: "+ioe.getMessage());
		} catch (CertificateException ce) {
			System.out.println("Error: "+ce.getMessage());
		} catch (KeyStoreException kse) {
			System.out.println("Error: "+kse.getMessage());
		}
	}
	
	// Parse the arguments, start and run the Server.
	public static void main(String[] args) {
		// Parse port arguments.
		boolean help = false;
		int portNumber = -1;
		for(int argindex = 0; argindex < args.length; argindex++) {
			String arg = args[argindex].toLowerCase();
			
			if(arg.equals("-h") || arg.equals("--help")) { help = true; }
			if(arg.equals("-p") || arg.equals("--port")) {
				if(argindex == args.length - 1) { // Final argument?
					System.out.println("No port specified. Using default: "+Server.DEFAULTPORT);
				} else {
					arg = args[argindex+1];
					try {
						portNumber = Integer.parseInt(arg);
						break; // No need for loop anymore.
					} catch(NumberFormatException nfe) {
						System.out.println("Couldn't parse port number. Using default: "+Server.DEFAULTPORT);
					}
				}
			}
		}
		// Simple guide for markers.
		if(help) {
			String message = "";
			message += "Syntax:\tjava assig2.tls.server.Server [-p|--port portnum][-h|--help]\n";
			message += "assig2.tls.server.Server by Sam Milburn.\n";
			message += "Options:\n";
			message += "\t-p or --port\tbind the server on the port number following this option.\n";
			message += "\t-h or --help\tdisplay this message.";
			System.out.println(message);
			return;
		}
		
		// Initialise and start the server.
		Server server;
		try {
			server = new Server(portNumber);
			server.processClients();
		} catch(IllegalArgumentException iae) {
			System.out.println("Error: "+iae.getMessage());
			return;
		}
	}
}

package assig2.tls.client;

// General & IO
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

// TCP/TLS Functionality
import java.net.UnknownHostException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * assig2.tls.client.Client communicates (via TCP) with a <b>TLSv1.3</b> Server.
 * @author Sam Milburn
 */
public class Client {
	private int tcpPort				= -1;
	private InetAddress address		= null;
	private SSLSocket socket		= null;
	
	/** 
	 * @return whether the messages could be exchanged.
	 * @throws ConnectException if we can't reach the host.
	 */
	private boolean exchangeMessages() throws ConnectException {
		if(this.socket == null || this.socket.isClosed()) {
			throw new ConnectException("Couldn't connect to the server.");
		}
		// Setup the connection.
		PrintWriter spw; BufferedReader br;
		try {
			spw = new PrintWriter(this.socket.getOutputStream(), true);
			br = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
		} catch (IOException e) {
			throw new ConnectException("Couldn't setup the message exchange.");
		}
		
		// Exchange messages.
		String sendme = "";
		if(this.address.getHostName().equals("localhost") || 
				this.address.getHostName().equals("127.0.0.1")) {
			sendme = "Hello, Server!"; // Communicating with my 'local server'.
		} else {
			// Proving that this works with a regular HTTPS server...
			// Download the root cert from a web browser (let's say amazon.com)
			// Replace the filepath in connectToHost with that cert and it should work.
			sendme = "GET / HTTP/1.1"+"\r\n"
					+ "Host: "+this.address.getHostName()+"\r\n"
					+ "User-Agent: assig2client"+"\r\n"
					+ "Accept: */*"+"\r\n"; 
		}
		
		spw.println(sendme); // Send request.
		System.out.println("Sending: ");
		for(String str: sendme.split("\r\n")) {
			System.out.println("\t"+str);
		}
		
		// Expecting response. 
		String resp = "";
		try {
			System.out.println("Receiving: ");
			try {
				// Safely read socket reader lines.
				while((resp = br.readLine()) != null) {
					System.out.println("\t"+resp);
				}
			// But *don't* hang. Default timeout takes forever.
			} catch(SocketTimeoutException se) {
				return true; // Timeout after a moment to grab the data.
			}
		} catch (IOException e) {
			throw new ConnectException("Couldn't receive the readLine.");
		} 
		return true;
	}
	
	/**
	 * @return whether the connection could close.
	 * @throws IOException if there's an issue closing.
	 */
	public boolean closeConnection() throws IOException {
		if(this.socket != null && !this.socket.isClosed()) {
			this.socket.close();
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * @return whether we can successfully connect and exchange messages.
	 */
	public boolean connectToHost() {
		try {
			// Load the trust manager and add it to the SSL/TLS context.
			System.out.println("Loading certificate...");
			String certdir = "Certificates";
			String certpath = "Certificates/milbursamuRA.com.pem"; 
			//certpath = "Certificates/google.com-rootcert"; 
			//certpath = "Certificates/amazon.com-rootcert";
			X509TrustManager tm = this.loadCustomTrustManager(certdir);
			SSLContext context = SSLContext.getInstance("TLSv1.3");
			context.init(null, new TrustManager[]{ tm }, new SecureRandom());
			
			// Create socket from the context and check the certificate chain can be trusted.
			// startHandshake() will throw an exception if it can't.
			System.out.println("Attempting to connect to "+this.address.getHostName()+"...");
			SSLSocketFactory socketFactory = (SSLSocketFactory) context.getSocketFactory();
			this.socket = (SSLSocket)socketFactory.createSocket(this.address, this.tcpPort);
			this.socket.setUseClientMode(true);
			this.socket.setSoTimeout(500); // 1/2-second timeout.
			
			// If this doesn't throw an exception, the server is authenticated.
			try {
				this.socket.startHandshake(); 
				List<X509Certificate> trustedCerts = Arrays.asList(tm.getAcceptedIssuers());
				// Ugly but structured lambda to collect the authority subject names.
				List<String> trustedAuthorities = 
						(trustedCerts.stream()
							.map(X509Certificate::getSubjectX500Principal)
							.collect(Collectors.toList()))
								.stream()
								.map(X500Principal::getName)
								.collect(Collectors.toList());
				System.out.println("Authenticated with trusted root authorities: ");
				for(String authority: trustedAuthorities) {
					System.out.println("\t"+authority);
				}
				System.out.println("Connected via TLSv1.3.");
			} catch(SSLHandshakeException sslhe) {
				this.socket.close();
				System.out.println("Error: Server couldn't be authenticated through certificate chain.");
				return false;
			}
			// Exchange messages now that the handshake works.
			this.exchangeMessages();
			return true;
		} catch (FileNotFoundException | CertificateException e) {
			System.out.println("Error: "+e.getMessage());
			return false;
		} catch(NoSuchAlgorithmException e) {
			System.out.println("Error: Couldn't get the SSLContext instance.");
			return false;
		} catch (KeyManagementException e) {
			System.out.println("Error: Couldn't initialise the SSLContext.");
			return false;
		} catch (IOException e) {
			System.out.println("Error: Couldn't create the socket.");
			return false;
		}
	}
	
	/**
	 * This can be done differently by combining the default trust store, 
	 * and a new one, but it's unnecessary for this assignment.
	 * @return a Trust Manager that trusts <b>only</b> the Root CA.
	 * @throws FileNotFoundException if we have an invalid/nonexistent file or func argument.
	 */
	private X509TrustManager loadCustomTrustManager(String certificatesDir) 
		throws FileNotFoundException, CertificateException {
		// Check if we can reach the file.
		if(certificatesDir == null || certificatesDir.isBlank()) {
			throw new FileNotFoundException("Invalid dir path argument.");
		}
		File file = new File(certificatesDir);
		if(!file.exists() || !file.isDirectory() || !file.canRead()) {
			throw new FileNotFoundException("Couldn't locate or read the certificate dir.");
		}
		
		// Initialise the trust store and add the certificate.
		KeyStore trustStore				= null;
		X509TrustManager trustManager	= null;
		try {
			trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(null); // Trust entries: 0.
			
			// Load the .pem certificates.
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			File[] subfiles = file.listFiles();
			for(File f: subfiles) {
				FileInputStream rootCertFIS = new FileInputStream(f);
				X509Certificate rootCert = (X509Certificate) cf.generateCertificate(rootCertFIS);
				rootCertFIS.close();
				trustStore.setCertificateEntry(f.getName(), rootCert);
			}
			
			// Prepare the custom TrustManager: Find via iterator.
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(trustStore);
			
			for(TrustManager tm: tmf.getTrustManagers()) {
				if(tm instanceof X509TrustManager) {
					trustManager = (X509TrustManager) tm; break;
				}
			}
			// We should be able to locate the manager.
			if(trustManager == null) {
				throw new CertificateException("Couldn't build the trust manager.");
			} else {
				return trustManager; // Valid return.
			}
		} catch(KeyStoreException kse) {
			throw new CertificateException("Couldn't initialise the certificate trust store.");
		} catch (NoSuchAlgorithmException e) {
			throw new CertificateException("Couldn't initialise the TrustManagerFactory.");
		} catch (CertificateException e) {
			throw new CertificateException("Couldn't load or store the certificate.");
		} catch (IOException e) {
			throw new FileNotFoundException("Couldn't read the file.");
		}
	}
	
	/**
	 * @param hostname a domain name or IP address.
	 * @param tcpPort a port from 1 to 49150.
	 * @throws IllegalArgumentException if there's an issue with the arguments.
	 */
	public Client(String hostname, int tcpPort) throws IllegalArgumentException {
		// Make sure we can reach the destination.
		if(hostname == null || hostname.isBlank()) {
			throw new IllegalArgumentException("Invalid hostname argument.");
		} else {
			try {
				this.address = InetAddress.getByName(hostname);
			} catch(UnknownHostException uhe) {
				throw new IllegalArgumentException("Couldn't locate the server by the hostname.");
			}
		}
		if(tcpPort <= 1 || tcpPort >= 49151) {
			throw new IllegalArgumentException("Port number in an invalid range.");
		} else {
			this.tcpPort = tcpPort;
		}
	}
	
	// Connect to the host, install the Root CA from their chain and exchange messages. 
	public static void main(String[] args) {
		// Grab the hostname and port.
		int tcpPort = -1; boolean help = false; String hostname = "";
		if(args.length == 0) { tcpPort = 443; hostname = "127.0.0.1"; }
		// Parse arguments through loop.
		for(int argindex = 0; argindex < args.length; argindex++) {
			String arg = args[argindex].toLowerCase();
			// Parse the port number.
			if(arg.equals("-p") || arg.equals("--port")) {
				if(argindex == args.length - 1) {
					// Last index, can't be followed by the port number.
					System.out.println("Error: no port number specified.");
					return;
				} else {
					// Next index is expected to be the port number.
					String portnum = args[argindex+1];
					try {
						tcpPort = Integer.parseInt(portnum);
						argindex += 2; // No need to parse the next one, skip to the one after that.
					} catch(NumberFormatException nfe) {
						System.out.println("Couldn't parse the port number.");
					}
				}
			}
			// Help menu
			else if(arg.equals("-h") || arg.equals("--help")) {
				help = true;
			}
			// Must be the hostname.
			else {
				hostname = arg;
			}
		}
		if(help) {
			String message = "";
			message += "Syntax:\tjava assig2.tls.client.Client hostname [-p|--port portnum][-h|--help]\n";
			message += "assig2.tls.client.Client by Sam Milburn.\n";
			message += "Options:\n";
			message += "\t-p or --port\tconnect to the host on the specified port.\n";
			message += "\t-h or --help\tdisplay this help message.";
			System.out.println(message);
			return;
		}
		// CLI arguments parsed.
		System.out.println("hostname: "+hostname+", port: "+tcpPort);
		
		try {
			Client client = new Client(hostname, tcpPort); // Default: 127.0.0.1.
			client.connectToHost();
			
			client.closeConnection();
		} catch(IllegalArgumentException iae) {
			System.out.println("Error: "+iae.getMessage());
		} catch(IOException ioe) {
			System.out.println("Error: "+ioe.getMessage());
		}
	}
}

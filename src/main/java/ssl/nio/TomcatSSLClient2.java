package ssl.nio;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;

/**
 *@description:
 *@author: cyq
 *@create: 2022/4/7 15:42
 */
public class TomcatSSLClient2 {
	private static final String SSL_TYPE = "SSL";
	private static final String X509 = "SunX509";
	private static final String KS_TYPE = "JKS";
	private SSLSocket sslSocket;

	public TomcatSSLClient2(String targetHost, int port) throws Exception {
		SSLContext sslContext = createSSLContext();
		SSLSocketFactory sslcntFactory =  sslContext.getSocketFactory();
		sslSocket = (SSLSocket) sslcntFactory.createSocket(targetHost, port);
		String[] supported = sslSocket.getSupportedCipherSuites();
		sslSocket.setTcpNoDelay(false);
		sslSocket.setEnabledCipherSuites(supported);
	}

	private SSLContext createSSLContext() throws Exception {
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(X509);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(X509);
		String clientKeyStoreFile = "c:\\client.jks";
		String cntPassphrase = "client";
		char[] cntPassword = cntPassphrase.toCharArray();
		KeyStore clientKeyStore = KeyStore.getInstance(KS_TYPE);
		clientKeyStore.load(new FileInputStream(clientKeyStoreFile), cntPassword);
		String serverKeyStoreFile = "c:\\.keystore";
		String svrPassphrase = "caoyouqian";
		char[] svrPassword = svrPassphrase.toCharArray();
		KeyStore serverKeyStore = KeyStore.getInstance(KS_TYPE);
		serverKeyStore.load(new FileInputStream(serverKeyStoreFile), svrPassword);
		kmf.init(clientKeyStore, cntPassword);
		tmf.init(serverKeyStore);
		SSLContext sslContext = SSLContext.getInstance(SSL_TYPE);
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		return sslContext;
	}

	public String sayToSvr(String sayMsg) throws IOException {
		BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
		PrintWriter ioWriter = new PrintWriter(sslSocket.getOutputStream());
		System.out.println(sayMsg.length());;
		ioWriter.println(sayMsg);
		ioWriter.flush();
		return ioReader.readLine();
	}

	public String sayBytesToSvr(int num) throws IOException {
		BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
		//PrintWriter ioWriter = new PrintWriter(sslSocket.getOutputStream());
		OutputStream writer = sslSocket.getOutputStream();
		writer.write(createBytes(num));
		writer.flush();
		return ioReader.readLine();
	}

	public void close() throws IOException {
		sslSocket.close();
	}

	private byte[] createBytes(int num){
		byte[] bytes = new byte[num];
		for (int i = 0; i < num; i++) {
			bytes[i] = 1;
		}
		return bytes;
	}

	public static void main(String[] args) throws Exception {
		TomcatSSLClient2 sslSocket = new TomcatSSLClient2("127.0.0.1", 28999);
		BufferedReader ioReader = new BufferedReader(new InputStreamReader(System.in));
		String sayMsg = "nihao";
		String svrRespMsg = "";
		int i = 0;
		while ((sayMsg = ioReader.readLine()) != null) {
			svrRespMsg = sslSocket.sayBytesToSvr(333050);
			if (svrRespMsg != null && !svrRespMsg.trim().equals("")) {
				System.out.println("服务器通过SSL协议响应:" + svrRespMsg);
			}
			i++;
		}
	}
}


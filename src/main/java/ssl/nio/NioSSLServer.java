package ssl.nio;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.util.Iterator;

/**
 *@description:
 *@author: cyq
 *@create: 2022/4/7 15:47
 */
public class NioSSLServer {
	private Selector selector;
	private static SSLContext sslContext;
	private static final String SSL_TYPE = "SSL";
	private static final String KS_TYPE = "JKS";
	private static final String X509 = "SunX509";
	private final static int PORT = 28999;

	public void run() throws Exception {
		while (true) {
			selector.select();
			Iterator<SelectionKey> it = selector.selectedKeys().iterator();
			while (it.hasNext()) {
				SelectionKey selectionKey = it.next();
				Handle handle = (Handle) selectionKey.attachment();
				if(handle == null){
					System.out.println("handle="+selectionKey);
				}
				it.remove();
				/*System.out.println("selector 获取的事件:"+selectionKey.toString()+" "+
						selectionKey.isValid()+" "+
						selectionKey.isReadable()+" "+
						selectionKey.isWritable()+" "+
						selectionKey.isConnectable()+" "+
						selectionKey.isAcceptable());*/
				handle.doHandle();
			}
		}
	}

	protected static SSLEngine createSSLEngine() {
		SSLEngine sslEngine = sslContext.createSSLEngine();
		sslEngine.setUseClientMode(false);
		sslEngine.setNeedClientAuth(true);
		return sslEngine;
	}

	private  void createServerSocket() throws Exception {
		ServerSocketChannel serverChannel = ServerSocketChannel.open();
		serverChannel.configureBlocking(false);
		selector = Selector.open();
		ServerSocket serverSocket = serverChannel.socket();
		serverSocket.setReuseAddress(true);
		serverSocket.setReceiveBufferSize(655360);//640KB
		serverSocket.bind(new InetSocketAddress(PORT));
		new Acceptor(selector,serverChannel);
	}

	private static void createSSLContext() throws Exception {
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(X509);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(X509);
		String serverKeyStoreFile = "c:\\.keystore";
		String svrPassphrase = "caoyouqian";
		char[] svrPassword = svrPassphrase.toCharArray();
		KeyStore serverKeyStore = KeyStore.getInstance(KS_TYPE);
		serverKeyStore.load(new FileInputStream(serverKeyStoreFile), svrPassword);
		kmf.init(serverKeyStore, svrPassword);
		String clientKeyStoreFile = "c:\\client.jks";
		String cntPassphrase = "client";
		char[] cntPassword = cntPassphrase.toCharArray();
		KeyStore clientKeyStore = KeyStore.getInstance(KS_TYPE);
		clientKeyStore.load(new FileInputStream(clientKeyStoreFile), cntPassword);
		tmf.init(clientKeyStore);
		sslContext = SSLContext.getInstance(SSL_TYPE);
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
	}

	public static void main(String[] args) throws Exception {
		NioSSLServer.createSSLContext();
		NioSSLServer server = new NioSSLServer();
		server.createServerSocket();
		server.run();
	}
}


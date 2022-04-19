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
import java.util.concurrent.atomic.AtomicInteger;

/**
 *@description:
 *@author: cyq
 *@create: 2022/4/7 15:47
 */
public class NioSSLServerTemp {
	private SSLEngine sslEngine;
	private Selector selector;
	private SSLContext sslContext;
	private ByteBuffer netInData;
	private ByteBuffer appInData;
	private ByteBuffer netOutData;
	private ByteBuffer appOutData;
	private static final String SSL_TYPE = "SSL";
	private static final String KS_TYPE = "JKS";
	private static final String X509 = "SunX509";
	private final static int PORT = 443;
	private  static AtomicInteger i = new AtomicInteger();

	public void run() throws Exception {
		createServerSocket();
		createSSLContext();
		createSSLEngine();
		createBuffer();
		while (true) {
			selector.select();
			Iterator<SelectionKey> it = selector.selectedKeys().iterator();
			while (it.hasNext()) {
				SelectionKey selectionKey = it.next();
				it.remove();
				handleRequest(selectionKey);
			}
		}
	}

	private void createBuffer() {
		SSLSession session = sslEngine.getSession();
		appInData = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());
		netInData = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
		appOutData = ByteBuffer.allocate(sslEngine.getSession().getApplicationBufferSize());
		netOutData = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
	}

	private void createSSLEngine() {
		sslEngine = sslContext.createSSLEngine();
		sslEngine.setUseClientMode(false);
	}

	private void createServerSocket() throws Exception {
		ServerSocketChannel serverChannel = ServerSocketChannel.open();
		serverChannel.configureBlocking(false);
		selector = Selector.open();
		ServerSocket serverSocket = serverChannel.socket();
		serverSocket.bind(new InetSocketAddress(PORT));
		serverChannel.register(selector, SelectionKey.OP_ACCEPT);
	}

	private void createSSLContext() throws Exception {
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

	private void handleRequest(SelectionKey key) throws Exception {
		if (key.isAcceptable()) {
			ServerSocketChannel ssc = (ServerSocketChannel) key.channel();
			SocketChannel channel = ssc.accept();
			channel.configureBlocking(false);
			System.out.println("收到建立请求事件");
			doHandShake(channel);
		}
		if (key.isReadable()) {
			if (sslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
				SocketChannel sc = (SocketChannel) key.channel();
				netInData.clear();
				appInData.clear();
				int num = sc.read(netInData);
				System.out.println("读取数据"+num);
				netInData.flip();
				SSLEngineResult engineResult = sslEngine.unwrap(netInData, appInData);
				doTask();
				if (engineResult.getStatus() == SSLEngineResult.Status.OK) {
					appInData.flip();
					byte[] bytes = new byte[appInData.limit()];
					appInData.get(bytes);
					System.out.println(new String(bytes));

				}
				sc.register(selector, SelectionKey.OP_WRITE);
			}
		}
		if (key.isWritable()) {
			//System.out.println("写回数据");
			SocketChannel sc = (SocketChannel) key.channel();
			netOutData.clear();
			appOutData = ByteBuffer.wrap(((i.incrementAndGet())+"Hello\n").getBytes());
			//printH();
			SSLEngineResult engineResult = sslEngine.wrap(appOutData, netOutData);
			doTask();
			netOutData.flip();
			appOutData.clear();
			while (netOutData.hasRemaining())
				sc.write(netOutData);
		//	key.interestOps(SelectionKey.OP_READ);
		}
	}

	private void doHandShake(SocketChannel sc) throws IOException {
		boolean handshakeDone = false;
		sslEngine.beginHandshake();
		SSLEngineResult.HandshakeStatus hsStatus = sslEngine.getHandshakeStatus();
		System.out.println("开始握手 "+hsStatus);

		while (!handshakeDone) {
			switch (hsStatus) {
				case FINISHED:
					System.out.println("开始握手：FINISHED");
					break;
				case NEED_TASK:
					System.out.println("开始握手：NEED_TASK");
					hsStatus = doTask();
					break;
				case NEED_UNWRAP:
					//System.out.println("开始握手：NEED_UNWRAP");
					netInData.clear();
					int red = sc.read(netInData);
					if(red > 0)
					System.out.println("从channel读取数据"+red);
					netInData.flip();
					do {
						SSLEngineResult engineResult = sslEngine.unwrap(netInData, appInData);
						System.out.println("解包之后的握手状态"+engineResult.getStatus());
						hsStatus = doTask();
					} while (hsStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP && netInData.remaining() > 0);
					netInData.clear();
					break;
				case NEED_WRAP:
					System.out.println("开始握手：NEED_WRAP");
					SSLEngineResult engineResult = sslEngine.wrap(appOutData, netOutData);
					System.out.println("打完之后的握手状态"+engineResult.getHandshakeStatus());
					hsStatus = doTask();
					netOutData.flip();
					sc.write(netOutData);
					netOutData.clear();
					break;
				case NOT_HANDSHAKING:
					System.out.println("开始握手：NOT_HANDSHAKING");
					sc.configureBlocking(false);
					sc.register(selector, SelectionKey.OP_READ);
					handshakeDone = true;
					break;
			}
		}
	}

	private SSLEngineResult.HandshakeStatus doTask() {
		Runnable task;
		while ((task = sslEngine.getDelegatedTask()) != null) {
			System.out.println("执行SSL验证任务");
			new Thread(task).start();
		}
		return sslEngine.getHandshakeStatus();
	}

	private synchronized static void printH(){
		new Thread(){
			@Override
			public void run() {
				try {
					Thread.sleep(1000);
				System.out.println(i.get());
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}

		}.start();
	}

	public static void main(String[] args) throws Exception {
		new NioSSLServerTemp().run();
	}
}


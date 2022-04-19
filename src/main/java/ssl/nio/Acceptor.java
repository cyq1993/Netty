package ssl.nio;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

/**
 *@description:
 *@author: cyq
 *@create: 2022/4/12 18:55
 */
public class Acceptor implements Handle {
	private volatile SelectionKey key;
	private ByteBuffer netInData;
	private ByteBuffer appInData;
	private ByteBuffer appOutData;
	private ByteBuffer netOutData;
	private SSLEngine sslEngine;

	public Acceptor(Selector selector,ServerSocketChannel serverChannel) throws ClosedChannelException {
		this.key = serverChannel.register(selector,SelectionKey.OP_ACCEPT,this);
	}

	@Override
	public void doHandle() throws Exception {
		init();
		handShake(key);
	}

	void init(){
		sslEngine = NioSSLServer.createSSLEngine();
		SSLSession session = sslEngine.getSession();
		appInData = ByteBuffer.allocate(session.getApplicationBufferSize());
		netInData = ByteBuffer.allocate(session.getPacketBufferSize());
		appOutData = ByteBuffer.allocate(session.getApplicationBufferSize());
		netOutData = ByteBuffer.allocate(session.getPacketBufferSize());
	}

	/**
	 * ����SSL����
	 * */
	private void handShake(SelectionKey key) throws Exception {
		if(key.isValid() && key.isAcceptable()){
			ServerSocketChannel ssc = (ServerSocketChannel) key.channel();
			SocketChannel channel = ssc.accept();
			channel.configureBlocking(false);
			doHandShake(channel);
		}
	}

	private void doHandShake(SocketChannel sc) throws IOException {
		boolean handshakeDone = false;
		sslEngine.beginHandshake();
		SSLEngineResult.HandshakeStatus hsStatus = sslEngine.getHandshakeStatus();
		System.out.println("��ʼ���� "+hsStatus);

		while (!handshakeDone) {
			switch (hsStatus) {
				case FINISHED:
					System.out.println("��ʼ���֣�FINISHED");
					break;
				case NEED_TASK:
					System.out.println("��ʼ���֣�NEED_TASK");
					hsStatus = doTask();
					break;
				case NEED_UNWRAP:
					//System.out.println("��ʼ���֣�NEED_UNWRAP");
					netInData.clear();
					int red = sc.read(netInData);
					if(red > 0)
 					System.out.println("��channel��ȡ����"+red);
					netInData.flip();
					do {
						SSLEngineResult engineResult = sslEngine.unwrap(netInData, appInData);
						System.out.println("���֮�������״̬"+engineResult.getHandshakeStatus());
						hsStatus = doTask();
					} while (hsStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP && netInData.remaining() > 0);
					netInData.clear();
					break;
				case NEED_WRAP:
					//System.out.println("��ʼ���֣�NEED_WRAP");
					SSLEngineResult engineResult = sslEngine.wrap(appOutData, netOutData);
					System.out.println("������"+engineResult);
					hsStatus = doTask();
					netOutData.flip();
					sc.write(netOutData);
					netOutData.clear();
					break;
				case NOT_HANDSHAKING:
					System.out.println("��ʼ���֣�NOT_HANDSHAKING");
					new Session(key.selector(),sslEngine,sc);
					handshakeDone = true;
					break;
			}
		}
	}

	private SSLEngineResult.HandshakeStatus doTask() {
		Runnable task;
		while ((task = sslEngine.getDelegatedTask()) != null) {
			System.out.println("ִ��SSL��֤����");
			new Thread(task).start();
		}
		return sslEngine.getHandshakeStatus();
	}

}

package ssl.nio;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

/**
 *@description:
 *@author: cyq
 *@create: 2022/4/12 15:43
 */
public class Session implements Handle {
	private SSLEngine sslEngine;
	private SelectionKey key;

	private Input input;
	private Output output;

	public Session(Selector selector, SSLEngine sslEngine,SocketChannel channel) throws ClosedChannelException {
		input = new Input();
		output = new Output(sslEngine.getSession().getApplicationBufferSize(),sslEngine.getSession().getPacketBufferSize());
		this.sslEngine = sslEngine;
		this.key = channel.register(selector,SelectionKey.OP_READ,this);
		System.out.println("key="+key);
	}

	private SocketChannel getChannel() {
		return (SocketChannel) key.channel();
	}

	private void close() throws IOException {
		if (key.channel().isOpen()) {
			key.channel().close();
		}
	}

	@Override
	public void doHandle() throws IOException {
		if(sslEngine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING){
			System.out.println("SSL没有完成握手"+sslEngine.getHandshakeStatus());
		}
		if (key.isReadable()) {
			if (-1 == input.doRead(this)) {
				close();
				return;
			}
		}

		if (key.isWritable()) {
			output.doWrite(this);
		}
	}

	public static final class Input {
		private ByteBuffer appInData;
		private ByteBuffer netInData;

		private void createInData(SSLEngine engine) {
			this.appInData = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
			this.netInData = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
		}

		private synchronized int doRead(Session s) throws IOException {
				if (appInData == null || netInData == null) {
					createInData(s.sslEngine);
				}

				netInData.clear();
				appInData.clear();
				int rc = s.getChannel().read(netInData);
				System.out.println("channel="+s.getChannel());
				if (rc > 0) {
					netInData.flip();
					SSLEngineResult engineResult = s.sslEngine.unwrap(netInData, appInData);
					doTask(s.sslEngine);
					if (engineResult.getStatus() == SSLEngineResult.Status.OK){
						appInData.flip();
						System.out.println("收到客户端数据:"+new String(appInData.array()));
					}
				s.getChannel().register(s.key.selector(),SelectionKey.OP_WRITE,s);
				}

				return rc;
		}
	}

	public static final class Output {
		private ByteBuffer appOutData;
		private ByteBuffer netOutData;

		private void createOutData(SSLEngine engine) {
			this.appOutData = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
			this.netOutData = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
		}
		public Output(int appOutDataSize, int netOutDataSize) {
			this.appOutData = ByteBuffer.allocate(appOutDataSize);
			this.netOutData = ByteBuffer.allocate(netOutDataSize);
		}

		private  synchronized int doWrite(Session s) throws IOException {
			/*if(appOutData == null){
				return 0;
			}*/
			appOutData = ByteBuffer.wrap("Hello\n".getBytes());
			SSLEngineResult engineResult = s.sslEngine.wrap(appOutData, netOutData);
			doTask(s.sslEngine);
			netOutData.flip();
			while (netOutData.hasRemaining()){
				s.getChannel().write(netOutData);
			}
			netOutData.compact();
		//	s.getChannel().register(s.key.selector(),SelectionKey.OP_READ,s);
		//	interestOps(s.key,SelectionKey.OP_WRITE,SelectionKey.OP_READ);
			return 0;
		}

	}

	private static  SSLEngineResult.HandshakeStatus doTask(SSLEngine sslEngine) {
		Runnable task;
		while ((task = sslEngine.getDelegatedTask()) != null) {
			System.out.println("执行SSL验证任务");
			new Thread(task).start();
		}
		return sslEngine.getHandshakeStatus();
	}

	public static final void interestOps(SelectionKey key,int remove, int add) {
		int cur = key.interestOps();
		int ops = (cur & ~remove) | add;
		if (cur != ops)
			key.interestOps(ops);
			key.selector().wakeup();
	}

}

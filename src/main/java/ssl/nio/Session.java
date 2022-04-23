package ssl.nio;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_TASK;

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
			this.appInData = ByteBuffer.allocate(819200);
			this.netInData = ByteBuffer.allocate(819200);
		}

		private synchronized int doRead(Session s) throws IOException {
				if (appInData == null || netInData == null) {
					createInData(s.sslEngine);
				}
				
				int rc ;//
				int len = 0;
			while ((rc = s.getChannel().read(netInData)) > 0 || netInData.position() != 0) {
					System.out.println("从channel中读入数据量："+rc);
					netInData.flip();
					System.out.println("netData"+netInData.position() + " "+netInData.limit());
					SSLEngineResult engineResult = s.sslEngine.unwrap(netInData, appInData);
					System.out.println("netData"+netInData.position() + " "+netInData.limit());
					doTask(s.sslEngine);
					netInData.compact();

					if (engineResult.getStatus() == SSLEngineResult.Status.OK){
						appInData.flip();
						byte[] bytes = new byte[appInData.limit()];
						appInData.get(bytes);
						System.out.println(engineResult.getHandshakeStatus()+"收到客户端数据:"+bytes.length);
						len+=bytes.length;
						/*for (byte b : bytes) {
							System.out.println(b);
						}*/
						appInData.compact();
					}else if(engineResult.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
						//报错无法从channel中读入数据
						System.out.println("Status"+engineResult.getStatus());
						break;
					}
					interestOps(s.key,0,SelectionKey.OP_WRITE);
					System.out.println("channel 注册读事件");
				}
			System.out.println("本次解析数据："+ len);
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
			interestOps(s.key,SelectionKey.OP_WRITE,SelectionKey.OP_READ);
			System.out.println("channel 取消写事件,注册读事件");
			return 0;
		}

	}

	private static  SSLEngineResult.HandshakeStatus doTask(SSLEngine sslEngine) {
		while(true) {
			Runnable task = sslEngine.getDelegatedTask();
			if (task == null) {
				return  sslEngine.getHandshakeStatus();
			}
			task.run();
		}
	}

	public static final void interestOps(SelectionKey key,int remove, int add) {
		int cur = key.interestOps();
		int ops = (cur & ~remove) | add;
		if (cur != ops)
			key.interestOps(ops);
			key.selector().wakeup();
	}

	/**
	 *    buf.clear();          // Prepare buffer for use
	 *    while (in.read(buf) >= 0 || buf.position != 0) {
	 *        buf.flip();
	 *        out.write(buf);
	 *        buf.compact();    // In case of partial write
	 *    }
	 *
	 *
	 * */

}

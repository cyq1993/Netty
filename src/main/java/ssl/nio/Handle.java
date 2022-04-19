package ssl.nio;

import java.io.IOException;

/**
 *@description: 处理IO事件
 *@author: cyq
 *@create: 2022/4/12 16:33
 */
public interface Handle {
	void doHandle() throws Exception;
}

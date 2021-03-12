package nthu.wcislab.upnpigd;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.stream.ChunkedWriteHandler;

public class WebSocketServer {
    private int port;
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    public WebSocketServer(int port) {
        this.port = port;
    }

    public void run() throws Exception {
        bossGroup = new NioEventLoopGroup();
        workerGroup = new NioEventLoopGroup();

        ServerBootstrap b = new ServerBootstrap();
        b.group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel.class)
            .childHandler(new ChannelInitializer<SocketChannel>() {

                @Override
                protected void initChannel(SocketChannel ch)
                        throws Exception {
                    ChannelPipeline pipeline = ch.pipeline();
                    pipeline.addLast("http-codec",
                            new HttpServerCodec());
                    pipeline.addLast("aggregator",
                            new HttpObjectAggregator(65536));
                    pipeline.addLast("http-chunked",
                            new ChunkedWriteHandler());
                    pipeline.addLast("handler",
                            new WebSocketServerHandler());
                }
            });

        b.bind(port).sync();
        System.out.println("Web socket server started at port " + port
                + '.');
        System.out
                .println("Open your browser and navigate to http://localhost:"
                        + port + '/');
    }

    public void stop() {
        bossGroup.shutdownGracefully();
        workerGroup.shutdownGracefully();
    }
}
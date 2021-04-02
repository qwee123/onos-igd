package nthu.wcislab.upnpigd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

import java.util.concurrent.ConcurrentHashMap;
import nthu.wcislab.upnpigd.requesthandler.*;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;

public class HttpServer {
    private int port;
    private static final Logger log = LoggerFactory.getLogger(HttpServer.class);

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    protected RouteMatcher routes;

    public HttpServer(int port) {
        this.port = port;
    }

    private void initRoutes(IfaceWatchable iface_watcher, PortmappingExecutor pm_executor) {
        routes = new RouteMatcher();

        routes.add("/checkalive", new CheckAliveHandler(iface_watcher));
        routes.add("/stats/iface", new StatsHandler.InterfaceHandler(iface_watcher));
        routes.add("/stats/extipaddr", new StatsHandler.ExtIpAddrHandler(iface_watcher));
        routes.add("/stats/wanconnstatus", new StatsHandler.WanConnStatus(iface_watcher));
        routes.add("/portmapping", new PortmappingSingleHandler(pm_executor));
        routes.add("/portmapping/range", new PortmappingRangeHandler(pm_executor));
        routes.noMatch = new ErrorHandler.NoMatchHandler();

    }

    public void run(IfaceWatchable iface_watcher, PortmappingExecutor pm_executor) throws Exception {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();

        initRoutes(iface_watcher, pm_executor);

        ServerBootstrap b = new ServerBootstrap();
        b.group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel.class)
            .handler(new LoggingHandler(LogLevel.INFO))
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) throws Exception {
                    ChannelPipeline p = ch.pipeline();
                    p.addLast(new HttpRequestDecoder()); //chunked_supported is enabled in default
                    p.addLast(new HttpResponseEncoder());
                    p.addLast(new HttpObjectAggregator(128 * 1024)); //bytes
                    p.addLast(new HttpServerHandler(HttpServer.this));
                }
            });

        b.bind(port).sync();
        log.info("Server listening on port: {}", port);
    }

    public void stop() {
        bossGroup.shutdownGracefully();
        workerGroup.shutdownGracefully();
    }

    protected static class RouteMatcher {
        private ConcurrentHashMap<String, HttpRequestHandleable> routes = new ConcurrentHashMap<>();
        private HttpRequestHandleable noMatch;

        public HttpRequestHandleable Match(String reqpath) {
            String path = cleanPath(reqpath);
            int lastIndex = path.length() - 1;
            if (lastIndex > 0 && path.charAt(lastIndex) == '/') {
                path = path.substring(0, lastIndex);
            }

            final HttpRequestHandleable handler = routes.get(path);
            if (handler != null) {
                return handler;
            } else {
                return noMatch;
            }
        }

        /*
        * This method will eliminate redundant '\' letter in the path.
        * e.g. "a/b//c" >> "a/b/c"
        */
        private String cleanPath(String path) {
            StringBuilder builder = new StringBuilder();
            boolean edge = false;
            int length = path.length();
            for (int i = 0; i < length; i++) {
                char c = path.charAt(i);
                if (c == '/') {
                    if (!edge) {
                        builder.append(c);
                    }
                    edge = true;
                } else {
                    builder.append(c);
                    edge = false;
                }
            }
            return builder.toString();
        }

        public void add(String path, HttpRequestHandleable handler) {
            if (path.length() > 1 && path.endsWith("/")) { //eliminate '/' letter at the end
                    path = path.substring(0, path.length() - 1);
                }
                routes.put(path, handler);
        }

        public void noMatch(HttpRequestHandleable handler) {
            noMatch = handler;
        }

    }
}

package nthu.wcislab.upnpigd;

import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.QueryStringDecoder;

import nthu.wcislab.upnpigd.requesthandler.*;

import static io.netty.util.CharsetUtil.UTF_8;
import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;

/* This Handler class is independent to each http request */
public class HttpServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private final HttpServer server;

    public HttpServerHandler(HttpServer server) {
        this.server = server;
    }

    /* This function is invoked twice continuously */
    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        FullHttpResponse response;
        String uri = request.uri();

        QueryStringDecoder queryStringDecoder = new QueryStringDecoder(uri, UTF_8);

        try {
            HttpRequestHandleable handler = server.routes.Match(queryStringDecoder.path());
            response = handler.handle(request);

            if (response == null) {
                throw new NullPointerException("Returned response is null");
            }

        } catch (Exception e) {
            e.printStackTrace();
            response = new DefaultFullHttpResponse(HTTP_1_1, INTERNAL_SERVER_ERROR,
                                    Unpooled.wrappedBuffer(e.toString().getBytes(UTF_8)));
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);
        if (!keepAlive) {
            ctx.write(response).addListener(ChannelFutureListener.CLOSE);
        } else {
            // Content-length is required to set to make sure the response data is fully replied.
            response.headers()
                .setInt(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
            ctx.write(response);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}

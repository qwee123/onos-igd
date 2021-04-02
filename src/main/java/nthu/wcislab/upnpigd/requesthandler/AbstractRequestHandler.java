package nthu.wcislab.upnpigd.requesthandler;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.DefaultFullHttpResponse;

import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import static io.netty.util.CharsetUtil.UTF_8;

import org.json.JSONObject;

public abstract class AbstractRequestHandler implements HttpRequestHandleable {

    public abstract FullHttpResponse handle(FullHttpRequest request);

    protected FullHttpResponse buildResponse(byte[] content, HttpResponseStatus status) {
        final ByteBuf byteBuf = Unpooled.copiedBuffer(content);
        return new DefaultFullHttpResponse(HTTP_1_1, status, byteBuf);
    }

    protected FullHttpResponse buildResponse(String content, HttpResponseStatus status) {
        final ByteBuf byteBuf = Unpooled.wrappedBuffer(content.getBytes(UTF_8));
        return new DefaultFullHttpResponse(HTTP_1_1, status, byteBuf);
    }

    protected FullHttpResponse buildResponse(JSONObject content, HttpResponseStatus status) {
        return buildResponse(content.toString(), status);
    }
}

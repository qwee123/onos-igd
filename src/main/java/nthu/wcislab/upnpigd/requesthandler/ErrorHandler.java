package nthu.wcislab.upnpigd.requesthandler;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;

public class ErrorHandler {

    public static class NoMatchHandler extends AbstractRequestHandler {
        public FullHttpResponse handle(FullHttpRequest request) {
            return buildResponse("404", HttpResponseStatus.NOT_FOUND);
        }
    }
}

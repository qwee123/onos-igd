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

    public static class MethodNotAllowedHandler extends AbstractRequestHandler {
        public FullHttpResponse handle(FullHttpRequest request) {
            return buildResponse("405", HttpResponseStatus.METHOD_NOT_ALLOWED);
        }
    }

    public static class BadRequestHandler extends AbstractRequestHandler {
        public FullHttpResponse handle(FullHttpRequest request) {
            return buildResponse("400", HttpResponseStatus.BAD_REQUEST);
        }
    }

    public static class InternalServerErrorHandler extends AbstractRequestHandler {
        public FullHttpResponse handle(FullHttpRequest request) {
            return buildResponse("500", HttpResponseStatus.INTERNAL_SERVER_ERROR);
        }
    }
}

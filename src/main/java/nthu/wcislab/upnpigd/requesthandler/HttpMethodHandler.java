package nthu.wcislab.upnpigd.requesthandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;

public class HttpMethodHandler extends AbstractRequestHandler {

    protected static final Logger log = LoggerFactory.getLogger(HttpMethodHandler.class);

    protected static final ErrorHandler.MethodNotAllowedHandler
            METHODNOTALLOWED = new ErrorHandler.MethodNotAllowedHandler();
    protected static final ErrorHandler.BadRequestHandler
            BADREQUEST = new ErrorHandler.BadRequestHandler();
    protected static final ErrorHandler.InternalServerErrorHandler
            INTERNALSERVERERROR = new ErrorHandler.InternalServerErrorHandler();

    @Override
    public FullHttpResponse handle(FullHttpRequest request) {
        switch (request.method().name()) {
            case "GET":
                return handleGet(request);
            case "POST":
                return handlePost(request);
            case "DELETE":
                return handleDelete(request);
            default:
                return METHODNOTALLOWED.handle(request);
        }
    }

    protected FullHttpResponse handleGet(FullHttpRequest request) {
        return METHODNOTALLOWED.handle(request);
    }

    protected FullHttpResponse handlePost(FullHttpRequest request) {
        return METHODNOTALLOWED.handle(request);
    }

    protected FullHttpResponse handleDelete(FullHttpRequest request) {
        return METHODNOTALLOWED.handle(request);
    }
}
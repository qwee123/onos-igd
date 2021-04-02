package nthu.wcislab.upnpigd.requesthandler;

public class IfaceWatcher extends HttpMethodHandler {
    protected IfaceWatchable iface_watcher;

    protected IfaceWatcher(IfaceWatchable iface_watcher) {
        this.iface_watcher = iface_watcher;
    }
}

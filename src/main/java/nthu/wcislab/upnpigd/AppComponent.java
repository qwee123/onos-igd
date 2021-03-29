/*
 * Copyright 2021-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nthu.wcislab.upnpigd;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onlab.packet.Ethernet;
import org.onlab.packet.ARP;
import org.onlab.packet.Ip4Address;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import java.util.List;
import javax.validation.constraints.Null;

import nthu.wcislab.upnpigd.requesthandler.OnosAgent;
import nthu.wcislab.upnpigd.requesthandler.StatsHandler.InterfaceHandler.InterfaceStats;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)

public class AppComponent implements OnosAgent {

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    private ApplicationId appId;

    private final Logger log = LoggerFactory.getLogger(getClass());

    private IGDPacketProcessor processor = new IGDPacketProcessor();

    private HttpServer httpServer;

    /**
     * Device_id and ext_iface_name should be filled in by onos-cfg"
     * Belowings are just some temporarily setup, or default config?
     */
    private final String router_device_id = "of:000012bf6e85b74f";
    private final String igd_ext_iface_name = "wan1";
    private final String igd_ext_ipaddr = "192.168.1.10/24";
    private PortNumber igd_ext_port;

    @Activate
    protected void activate() {
        log.info("Activating...");
        appId = coreService.registerApplication("nthu.wcislab.upnpigd");

        packetService.addProcessor(processor, PacketProcessor.director(2));

        try {
            init();
            requestIntercepts();
            startServer();
            log.info("Started " + appId.id());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        stopServer();
        log.info("Stopped");
    }

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void init() {
        DeviceId router_id = DeviceId.deviceId(router_device_id);
        List<Port> port_list = deviceService.getPorts(router_id);

        for (Port port : port_list) {
            if (port.annotations().value("portName").equals(igd_ext_iface_name)) {
                igd_ext_port = port.number();
                log.info("External IGD port detected:\n{}", port.toString());
                break;
            }
        }

        if (igd_ext_port == null) {
            log.error("External IGD port with name {} is not found." +
             "Please check your network topology and then restart the app", igd_ext_iface_name);
             throw new NullPointerException("No IGD external interface found.");
        }
    }

    private void startServer() {
        httpServer = new HttpServer(40000);
        try {
            httpServer.run(AppComponent.this);
        } catch (Exception e) {
            log.info("got exception {}", e);
        }
    }

    private void stopServer() {
        httpServer.stop();
    }

    public InterfaceStats GetIGDExtIfaceStats() {
        DeviceId router_id = DeviceId.deviceId(router_device_id);
        Port port = deviceService.getPort(router_id, igd_ext_port);
        PortStatistics stats = deviceService.getStatisticsForPort(router_id, igd_ext_port);

        InterfaceStats ret = new InterfaceStats();
        ret.iface_status = port.isEnabled();
        ret.obytes = stats.bytesSent();
        ret.ibytes = stats.bytesReceived();
        ret.opackets = stats.packetsSent();
        ret.ipackets = stats.packetsReceived();

        /*
        Baud rate is not bit rate. Two values will be identical only if the interface
        transmits siganls only through two symbol(0, 1), so each cycle(?) of modulation
        only contains one bit.

        Anyway, use bitrate instead for now.
        */
        ret.baudrate = port.portSpeed();

        return ret;
    }

    private class IGDPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext packet) {

            InboundPacket pkt = packet.inPacket();
            ConnectPoint cp = pkt.receivedFrom();

            Ethernet frame = pkt.parsed();
            if (frame.getEtherType() != Ethernet.TYPE_ARP) {
                return;
            }

            ARP arp_packet = (ARP) frame.getPayload();
            if (arp_packet.getProtocolType() != ARP.PROTO_TYPE_IP) {
                return;
            }

            Ip4Address src_ip4 = Ip4Address.valueOf(arp_packet.getSenderProtocolAddress());
            log.info("Receive ARP packet: ");
            log.info("From switch: {}", cp.deviceId());
            log.info("Sent by:  ip4: {}", src_ip4);
        }
    }
}

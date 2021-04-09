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
import org.onlab.packet.IPv4;
import org.onlab.packet.ARP;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import java.util.List;
import javax.validation.constraints.Null;
import javax.xml.crypto.Data;

import nthu.wcislab.upnpigd.portmapping.DatapathExecutable;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.Protocol;
import nthu.wcislab.upnpigd.portmapping.PortmappingExecutor.PortmappingEntry.RemoteHostDetail;
import nthu.wcislab.upnpigd.requesthandler.IfaceWatchable;
import nthu.wcislab.upnpigd.requesthandler.StatsHandler.InterfaceHandler.InterfaceStats;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)

public class AppComponent {

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

    private PortmappingProcessor portmappingProcessor;
    private OPFIfaceWatcher ifaceWatcher;

    private PortmappingExecutor portmappingExecutor;

    /**
     * Device_id and ext_iface_name should be filled in by onos-cfg"
     * Belowings are just some temporarily setup, or default config?
     */
    private final String router_device_id = "of:000012bf6e85b74f";
    private final String igd_ext_iface_name = "wan1";
    private final String igd_ext_ipaddr = "192.168.1.10/24";
    private PortNumber igd_ext_port;
    private int basepriority = 20;
    private int infinitepriority = 9999; //For deleteRules

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

        portmappingProcessor = new PortmappingProcessor();
        ifaceWatcher = new OPFIfaceWatcher();
        portmappingExecutor = new PortmappingExecutor(portmappingProcessor);
    }

    private void startServer() {
        httpServer = new HttpServer(40000);
        try {
            httpServer.run(ifaceWatcher, portmappingExecutor);
        } catch (Exception e) {
            log.info("got exception {}", e);
        }
    }

    private void stopServer() {
        httpServer.stop();
    }

    private class PortmappingProcessor implements DatapathExecutable {
        public boolean UpdateRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost) {
            AddRuleForEntry(entry, rhost);
            return true;
        }

        public boolean AddRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost) {
            TrafficSelector.Builder selector = buildMatchRule(entry, rhost);
            TrafficTreatment.Builder treatment = buildAction(entry, rhost);

            int priority = basepriority + rhost.GetRhostByIpPrefix().prefixLength();
            FlowRule rule = DefaultFlowRule.builder()
                .withSelector(selector.build())
                .withTreatment(treatment.build())
                .forDevice(DeviceId.deviceId(router_device_id))
                .withPriority(priority)
                .makeTemporary(rhost.GetLeaseDuration())
                .fromApp(appId)
                .build();
            flowRuleService.applyFlowRules(rule);

            return true;
        }

        public boolean DeleteRuleForEntry(PortmappingEntry entry, RemoteHostDetail rhost) {
            TrafficSelector.Builder selector = buildMatchRule(entry, rhost);

            int priority = basepriority + rhost.GetRhostByIpPrefix().prefixLength();
            FlowRule rule = DefaultFlowRule.builder()
                .withSelector(selector.build())
                .forDevice(DeviceId.deviceId(router_device_id))
                .makeTemporary(0)
                .withPriority(priority)
                .fromApp(appId)
                .build();
            flowRuleService.removeFlowRules(rule);

            return true;
        }

        private TrafficSelector.Builder buildMatchRule(PortmappingEntry entry, RemoteHostDetail rhost) {
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

            selector.matchEthType(Ethernet.TYPE_IPV4);

            if (entry.GetProtocol() == Protocol.TCP) {
                selector.matchIPProtocol(IPv4.PROTOCOL_TCP);
                selector.matchTcpDst(TpPort.tpPort(entry.GetExternalPort()));
            } else {
                selector.matchIPProtocol(IPv4.PROTOCOL_UDP);
                selector.matchUdpDst(TpPort.tpPort(entry.GetExternalPort()));
            }


            IpPrefix rhost_prefix = rhost.GetRhostByIpPrefix();
            if (!rhost_prefix.equals(IpPrefix.valueOf("0.0.0.0/0"))) {
                selector.matchIPSrc(rhost_prefix);
            }

            return selector;
        }

        private TrafficTreatment.Builder buildAction(PortmappingEntry entry, RemoteHostDetail rhost) {
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();

            if (entry.GetProtocol() == Protocol.TCP) {
                treatment.setTcpDst(TpPort.tpPort(entry.GetInternalPort()));
            } else {
                treatment.setUdpDst(TpPort.tpPort(entry.GetInternalPort()));
            }

            treatment.setIpDst(entry.GetInternalHostByIpAddress());

            return treatment;
        }
    }

    private class OPFIfaceWatcher implements IfaceWatchable {
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

        public String GetIGDExtAddr() {
            return igd_ext_ipaddr;
        }

        public String GetIGDDeviceID() {
            return router_device_id;
        }
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

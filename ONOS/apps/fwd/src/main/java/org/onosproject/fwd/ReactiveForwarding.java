/*
 * Copyright 2014-present Open Networking Laboratory
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
package org.onosproject.fwd;

import com.google.common.collect.ImmutableSet;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.util.ImmutableByteSequence;
import org.onlab.util.Tools;
import org.onosproject.bmv2.api.runtime.*;
import org.onosproject.bmv2.api.service.Bmv2Controller;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.ExtensionSelector;
import org.onosproject.net.flow.instructions.ExtensionTreatment;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.onosproject.bmv2.api.context.Bmv2DefaultConfiguration.parse;
import static org.slf4j.LoggerFactory.getLogger;

/*----------------*/
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
//import com.google.common.testing.EqualsTester;
//import org.junit.Before;
//import org.junit.Test;

import org.onosproject.bmv2.api.context.Bmv2Configuration;
import org.onosproject.bmv2.api.context.Bmv2DefaultConfiguration;

import java.io.BufferedReader;
import java.io.InputStreamReader;

//import static org.hamcrest.MatcherAssert.assertThat;
//import static org.hamcrest.Matchers.is;
/*--------------------*/


/**
 * Sample reactive forwarding application.
 */
@Component(immediate = true)
public class ReactiveForwarding {

    private static final int DEFAULT_TIMEOUT = 10;
    private static final int DEFAULT_PRIORITY = 10;

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService cfgService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    private ApplicationId appId;

    @Property(name = "packetOutOnly", boolValue = false,
            label = "Enable packet-out only forwarding; default is false")
    private boolean packetOutOnly = false;

    @Property(name = "packetOutOfppTable", boolValue = false,
            label = "Enable first packet forwarding using OFPP_TABLE port " +
                    "instead of PacketOut with actual port; default is false")
    private boolean packetOutOfppTable = false;

    @Property(name = "flowTimeout", intValue = DEFAULT_TIMEOUT,
            label = "Configure Flow Timeout for installed flow rules; " +
                    "default is 10 sec")
    private int flowTimeout = DEFAULT_TIMEOUT;

    @Property(name = "flowPriority", intValue = DEFAULT_PRIORITY,
            label = "Configure Flow Priority for installed flow rules; " +
                    "default is 10")
    private int flowPriority = DEFAULT_PRIORITY;

    @Property(name = "ipv6Forwarding", boolValue = false,
            label = "Enable IPv6 forwarding; default is false")
    private boolean ipv6Forwarding = false;

    @Property(name = "matchDstMacOnly", boolValue = false,
            label = "Enable matching Dst Mac Only; default is false")
    private boolean matchDstMacOnly = false;

    @Property(name = "matchVlanId", boolValue = false,
            label = "Enable matching Vlan ID; default is false")
    private boolean matchVlanId = false;

    @Property(name = "matchIpv4Address", boolValue = false,
            label = "Enable matching IPv4 Addresses; default is false")
    private boolean matchIpv4Address = false;

    @Property(name = "matchIpv4Dscp", boolValue = false,
            label = "Enable matching IPv4 DSCP and ECN; default is false")
    private boolean matchIpv4Dscp = false;

    @Property(name = "matchIpv6Address", boolValue = false,
            label = "Enable matching IPv6 Addresses; default is false")
    private boolean matchIpv6Address = false;

    @Property(name = "matchIpv6FlowLabel", boolValue = false,
            label = "Enable matching IPv6 FlowLabel; default is false")
    private boolean matchIpv6FlowLabel = false;

    @Property(name = "matchTcpUdpPorts", boolValue = false,
            label = "Enable matching TCP/UDP ports; default is false")
    private boolean matchTcpUdpPorts = false;

    @Property(name = "matchIcmpFields", boolValue = false,
            label = "Enable matching ICMPv4 and ICMPv6 fields; " +
                    "default is false")
    private boolean matchIcmpFields = false;

    //TODO:用一个map来存储tableIndex和tableNmae的映射
    public HashMap<String, Integer> NameToIndex;

    //TODO：默认情况的，只有一种json文件
    public boolean loadconfig_OK = false;
    public Bmv2Configuration config;

    //TODO:多个json文件时，根据不同的deviceID存储不同的json文件
    public HashMap<String,Bmv2Configuration> DeviceIdToConfig;
    public HashMap<String,String> DeviceIdToJsonFile;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    public Bmv2Controller controller;

    @Property(name = "ignoreIPv4Multicast", boolValue = false,
            label = "Ignore (do not forward) IPv4 multicast packets; default is false")
    private boolean ignoreIpv4McastPackets = false;

    private final TopologyListener topologyListener = new InternalTopologyListener();

    //TODO:根据不同的deviceid读取不同的json文件
    public Bmv2Configuration loadconfig(String deviceId) throws Exception {
        //TODO:如果从未加载过，读取的json文件并解析存储
        if (!DeviceIdToConfig.containsKey(deviceId)) {
            JsonObject json = Json.parse(new BufferedReader(new InputStreamReader(
                    this.getClass().getResourceAsStream(DeviceIdToJsonFile.get(deviceId))))).asObject();
            Bmv2DefaultConfiguration configNow = Bmv2DefaultConfiguration.parse(json);
            System.out.println("Load oK!");
            //TODO:打印所有的表

            for (int i = 0; i < configNow.tables().size(); i++) {
                //System.out.println(config.table(i).toString());
                System.out.print("tableIndex=" + i + "  ");
                System.out.println(configNow.table(i).name());
                NameToIndex.put(configNow.table(i).name(), i);
                System.out.println("--------------------------------------------");
            }
            //TODO：把加载的json解析后的配置存储起来
            DeviceIdToConfig.put(deviceId,configNow);
        }
        //TODO:返回
        return DeviceIdToConfig.get(deviceId);
    }

    //TODO:加载默认的json文件
    public Bmv2Configuration loadconfig() throws Exception {
        //TODO:读取的json文件
        if (loadconfig_OK == false) {
            JsonObject json = Json.parse(new BufferedReader(new InputStreamReader(
                    this.getClass().getResourceAsStream("/default.json")))).asObject();
            config = Bmv2DefaultConfiguration.parse(json);
            System.out.println("Load oK!");

            //TODO:打印所有的表
            for (int i = 0; i < config.tables().size(); i++) {
                //System.out.println(config.table(i).toString());
                System.out.print("tableIndex=" + i + "  ");
                System.out.println(config.table(i).name());
                NameToIndex.put(config.table(i).name(), i);
                System.out.println("--------------------------------------------");
            }
            loadconfig_OK = true;
        }
        return this.config;
    }

    //TODO：给RM1下发具体流表内容----------------------------------------------------
    //table0: 域内sid_flag_0
    public FlowRule sid_flag_0(String deviceID) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        //Ip4Prefix dstPrefix = Ip4Prefix.valueOf("10.0.0.1/32");

        //System.out.println("dstPrefix oK!");
        byte[] sid=new byte[36];
        for(int i=0;i<36;i++){
            sid[i]=(byte)i;
        }
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get","sid",sid)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_flag")
                .addParameter("flag", 0)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("sid_flag"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table0: 域间sid_flag_1
    public FlowRule sid_flag_1(String deviceID) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        //Ip4Prefix dstPrefix = Ip4Prefix.valueOf("10.0.0.1/32");

        //System.out.println("dstPrefix oK!");
        byte[] sid=new byte[36];
        for(int i=0;i<36;i++){
            sid[35-i]=(byte)i;
        }
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get","sid",sid)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_flag")
                .addParameter("flag", 1)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("sid_flag"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table1: 域内交付,sid_nid_ip-h2
    public FlowRule sid_nid_ip_h2(String deviceID) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.3/32");

        //System.out.println("dstPrefix oK!");
        byte[] sid=new byte[36];
        for(int i=0;i<36;i++){
            sid[i]=(byte)i;
        }
        byte[] nid=new byte[16];
        for(int i=0;i<16;i++){
            nid[i]=(byte)(i);
        }
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get","sid",sid)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_nid_ip")
                .addParameter("nid", nid)
                .addParameter("ip",0xc0a80a03)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("sid_nid_ip"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }


    //table2: 域间交付,sid_pid_ip-h3
    public FlowRule sid_pid_ip_h3(String deviceID) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.4/32");

        //System.out.println("dstPrefix oK!");
        byte[] sid=new byte[36];
        for(int i=0;i<36;i++){
            sid[35-i]=(byte)(i);
        }
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get","sid",sid)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_pid_ip")
                .addParameter("pid", 0x50494431)
                .addParameter("ip",0xc0a80a04)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("sid_pid_ip"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table3: table ip_port-h3
    public FlowRule rm_ip_port_h3( String deviceID ) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.4/32");

        System.out.println("dstPrefix oK!");
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchLpm("ipv4", "dstAddr", dstPrefix.address().toOctets(), dstPrefix.prefixLength())
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_egress_port")
                .addParameter("port", 3)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("ip_port"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table3: table ip_port-h2
    public FlowRule rm_ip_port_h2( String deviceID ) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.3/32");

        System.out.println("dstPrefix oK!");
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchLpm("ipv4", "dstAddr", dstPrefix.address().toOctets(), dstPrefix.prefixLength())
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_egress_port")
                .addParameter("port", 2)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("ip_port"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //给RM1下发流表结束-------------------------------------------------------------


    //TODO:给BR1下发具体流表内容--------------------------------------------------
    //table0: get_inter_pid_port-h2
    public FlowRule get_inter_pid_ip_h2(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.20.2/32");

        //System.out.println("dstPrefix oK!");
        //int pid1=0x50494431;
          //byte[] pid1=new byte[4];
        //pid1[0]='P';
        //pid1[1]='I';
        //pid1[2]='D';
        //pid1[3]='1';
        byte pid1[] = {'P', 'I', 'D', '1'};
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get", "pid1", pid1)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_ip")
                .addParameter("ip", 0xc0a81402)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("get_inter_pid_ip"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table1: get_to_rm
    public FlowRule get_to_rm(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.1/32");

        //System.out.println("dstPrefix oK!");

        int version_type = 160;
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get", "version_type", version_type)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_ip")
                .addParameter("ip", 0xc0a80a01)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("get_to_rm"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }


    //table2: data_pids_o_subtract
    public FlowRule data_pids_o_subtract(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.1/32");

        //System.out.println("dstPrefix oK!");
        int version_type = 161;
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("data", "version_type", version_type)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_pids_o")
                //.addParameter("pid_o")
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("data_pids_o_subtract"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table3: data_nid_c_ip
    public FlowRule data_nid_c_ip(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.2/32");

        //System.out.println("dstPrefix oK!");

        byte[] nid_c = new byte[15];
        for (int i = 0; i < 15; i++) {
            nid_c[i] = (byte) (i);
        }
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("data", "nid_c", nid_c)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_ip")
                .addParameter("ip", 0xc0a80a02)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("data_nid_c_ip"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table6: table ip_port-h1
    public FlowRule ip_port_h1(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.20.2/32");

        System.out.println("dstPrefix oK!");
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchLpm("ipv4", "dstAddr", dstPrefix.address().toOctets(), dstPrefix.prefixLength())
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_egress_port")
                .addParameter("port", 2)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("ip_port"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table6: table ip_port-h1
    public FlowRule ip_port_h2(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.2/32");

        System.out.println("dstPrefix oK!");
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchLpm("ipv4", "dstAddr", dstPrefix.address().toOctets(), dstPrefix.prefixLength())
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_egress_port")
                .addParameter("port", 3)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("ip_port"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }


    //给BR1下发流表结束-----------------------------------------------------------------------------------

    //TODO:给BR2下发流表-----------------------------------------
    //table1: get_to_rm
    public FlowRule br2_get_to_rm(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.20.1/32");

        //System.out.println("dstPrefix oK!");

        int version_type = 160;
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get", "version_type", version_type)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_ip")
                .addParameter("ip", 0xc0a81401)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("get_to_rm"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table5: data_inter_pid_ip-h2
    public FlowRule br2_data_inter_pid_ip_h2(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.4/32");

        //System.out.println("dstPrefix oK!");
        byte pid1[] = {'P', 'I', 'D', '1'};
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("data", "pid1", pid1)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_ip")
                .addParameter("ip", 0xc0a80a04)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("data_inter_pid_ip"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table:ip_port
    public FlowRule br2_ip_port_h1(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.20.1/32");

        System.out.println("dstPrefix oK!");
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchLpm("ipv4", "dstAddr", dstPrefix.address().toOctets(), dstPrefix.prefixLength())
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_egress_port")
                .addParameter("port", 1)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("ip_port"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }
    //table:ip_port
    public FlowRule br2_ip_port_h2(String deviceID) throws Exception {
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration = loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.10.4/32");

        System.out.println("dstPrefix oK!");
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchLpm("ipv4", "dstAddr", dstPrefix.address().toOctets(), dstPrefix.prefixLength())
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_egress_port")
                .addParameter("port", 2)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector = DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector=" + selector.toString());

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment=" + treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("ip_port"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }


    //给BR2下发流表结束-------------------------------------------

    //TODO:给RM2下发流表---------------------------------------------------------------------------------
    //table0: 域间sid_flag_0
    public FlowRule rm2_sid_flag_0(String deviceID) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        //Ip4Prefix dstPrefix = Ip4Prefix.valueOf("10.0.0.1/32");

        //System.out.println("dstPrefix oK!");
        byte[] sid=new byte[36];
        for(int i=0;i<36;i++){
            sid[35-i]=(byte)i;
        }
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get","sid",sid)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_flag")
                .addParameter("flag", 0)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("sid_flag"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table1: 域内交付,sid_nid_ip-h2
    public FlowRule rm2_sid_nid_ip_h2(String deviceID) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.20.3/32");

        //System.out.println("dstPrefix oK!");
        byte[] sid=new byte[36];
        for(int i=0;i<36;i++){
            sid[35-i]=(byte)i;
        }
        byte[] nid=new byte[16];
        for(int i=0;i<16;i++){
            nid[i]=(byte)(i);
        }
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchExact("get","sid",sid)
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_nid_ip")
                .addParameter("nid", nid)
                .addParameter("ip",0xc0a81403)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("sid_nid_ip"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //table3: table ip_port-h3
    public FlowRule rm2_ip_port_h3( String deviceID ) throws Exception{
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        DeviceId myDeviceId = DeviceId.deviceId(deviceID);
        Bmv2Configuration myConfiguration =loadconfig(deviceID);

        Ip4Prefix dstPrefix = Ip4Prefix.valueOf("192.168.20.3/32");

        System.out.println("dstPrefix oK!");
        ExtensionSelector extSelector = Bmv2ExtensionSelector.builder()
                .forConfiguration(myConfiguration)
                .matchLpm("ipv4", "dstAddr", dstPrefix.address().toOctets(), dstPrefix.prefixLength())
                .build();

        System.out.println("extSelector oK!");
        System.out.println(extSelector.toString());
        ExtensionTreatment extTreatment = Bmv2ExtensionTreatment.builder()
                .forConfiguration(myConfiguration)
                .setActionName("set_egress_port")
                .addParameter("port", 2)
                .build();
        System.out.println("extTreatment oK!");
        System.out.println(extTreatment.toString());

        TrafficSelector selector=DefaultTrafficSelector.builder()
                .extension(extSelector, myDeviceId)
                .build();

        System.out.println("selector oK!");
        System.out.println("selector="+selector.toString());

        TrafficTreatment treatment=DefaultTrafficTreatment.builder()
                .extension(extTreatment, myDeviceId)
                .build();
        System.out.println("treatment oK!");
        System.out.println("treatment="+treatment.toString());

        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(myDeviceId)
                .fromApp(myAppId)
                .forTable(NameToIndex.get("ip_port"))
                .withSelector(selector)
                .withTreatment(treatment)
                .makePermanent()
                .withPriority(100)
                .build();

        System.out.println("rule!");

        System.out.println(rule.toString());
        return rule;
    }

    //给RM2下发流表结束----------------------------------------------------------------------------------


 /*这一部分现在在重新理清Context与deviceID的绑定之后不用了
   //TODO:根据json文件的名字加载到 Bmv2DefaultConfiguration中
    public Bmv2DefaultConfiguration loadDefaultConfiguration(String jsonName) {
        try {
            JsonObject json = Json.parse(new BufferedReader(new InputStreamReader(
                    ReactiveForwarding.class.getResourceAsStream(jsonName)))).asObject();
            return parse(json);
        } catch (IOException e) {
            throw new RuntimeException("Unable to load default configuration", e);
        }
    }


    //TODO:把json文件喂给特定的bmv2
    public void load_josn_to_bmv2(String jsonName,String deviceName){
        //TODO:重大突破！！！加载对应的json文件
        try {
            DeviceId myDeviceId = DeviceId.deviceId(deviceName);
            System.out.println(controller.toString());
            Bmv2DeviceAgent agent = controller.getAgent(myDeviceId);
            agent.resetState();
            System.out.println(agent.deviceId());
            Bmv2DefaultConfiguration bmv2DefaultConfiguration=loadDefaultConfiguration(jsonName);
            agent.uploadNewJsonConfig(bmv2DefaultConfiguration.json().toString());
            agent.swapJsonConfig();



            System.out.println(deviceName+"加载"+jsonName+"成功");
        } catch (Exception e) {
            System.out.println(deviceName+"加载"+jsonName+"失败");
            System.out.println(e.toString());
        }

    }*/


    @Activate
    public void activate(ComponentContext context) {
        //TODO：初始化
        NameToIndex = new HashMap<String, Integer>();
        DeviceIdToConfig = new HashMap<String,Bmv2Configuration>();

        DeviceIdToJsonFile = new HashMap<String,String>();

        DeviceIdToJsonFile.put("bmv2:127.0.0.1:41001#3","/default_rm1.json");
        DeviceIdToJsonFile.put("bmv2:127.0.0.1:41002#4","/default_br1.json");
        DeviceIdToJsonFile.put("bmv2:127.0.0.1:41003#5","/default_br2.json");
        DeviceIdToJsonFile.put("bmv2:127.0.0.1:41004#6","/default_rm2.json");

        //TOTO:设置默认的参数

        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("org.onosproject.fwd");

        packetService.addProcessor(processor, PacketProcessor.director(2));
        topologyService.addListener(topologyListener);
        readComponentConfiguration(context);
        requestIntercepts();

        System.out.println("Hello FWD!");

        log.info("Hello ONOS! {} { } ___ {}",appId.toString(),"test ww");


        //load_josn_to_bmv2("/default_rm.json","bmv2:127.0.0.1:40001#1");
        //load_josn_to_bmv2("/default.json","bmv2:127.0.0.1:40002#2");
//TODO：apply RM1
        try {
            flowRuleService.applyFlowRules(sid_flag_0("bmv2:127.0.0.1:41001#3"));
            flowRuleService.applyFlowRules( sid_pid_ip_h3("bmv2:127.0.0.1:41001#3") );
            flowRuleService.applyFlowRules(sid_flag_1("bmv2:127.0.0.1:41001#3"));
            flowRuleService.applyFlowRules(sid_nid_ip_h2("bmv2:127.0.0.1:41001#3"));
            flowRuleService.applyFlowRules(rm_ip_port_h2("bmv2:127.0.0.1:41001#3"));
            flowRuleService.applyFlowRules(rm_ip_port_h3("bmv2:127.0.0.1:41001#3"));

            //--------------------RM、BR分界线--------------------------

            //TODO:休息1秒钟，看看效果
            System.out.println("_______________begin_to_sleep_________________________");
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            System.out.println("\n---------------------------------\n");
//TODO:apply BR1
            //《《《《《《《《《《《《《《
            flowRuleService.applyFlowRules(get_inter_pid_ip_h2("bmv2:127.0.0.1:41002#4"));
            flowRuleService.applyFlowRules(get_to_rm("bmv2:127.0.0.1:41002#4"));
            flowRuleService.applyFlowRules(data_pids_o_subtract("bmv2:127.0.0.1:41002#4"));
            flowRuleService.applyFlowRules(data_nid_c_ip("bmv2:127.0.0.1:41002#4"));
            //flowRuleService.applyFlowRules(data_intra_pid_ip_h1("bmv2:127.0.0.1:41002#4"));
            //flowRuleService.applyFlowRules(data_inter_pid_ip_h2("bmv2:127.0.0.1:41002#4"));
            //flowRuleService.applyFlowRules(data_inter_pid_ip_h3("bmv2:127.0.0.1:41002#4"));
            flowRuleService.applyFlowRules(ip_port_h1("bmv2:127.0.0.1:41002#4"));
            flowRuleService.applyFlowRules(ip_port_h2("bmv2:127.0.0.1:41002#4"));

//TODO:apply BR2
            flowRuleService.applyFlowRules(br2_get_to_rm("bmv2:127.0.0.1:41003#5"));
            flowRuleService.applyFlowRules(br2_ip_port_h1("bmv2:127.0.0.1:41003#5"));
            flowRuleService.applyFlowRules(br2_ip_port_h2("bmv2:127.0.0.1:41003#5"));
            flowRuleService.applyFlowRules(br2_data_inter_pid_ip_h2("bmv2:127.0.0.1:41003#5"));

//TODO:apply RM2
            //《《《《《《《《《《《《《《
            flowRuleService.applyFlowRules(rm2_sid_flag_0("bmv2:127.0.0.1:41004#6"));
            flowRuleService.applyFlowRules(rm2_sid_nid_ip_h2("bmv2:127.0.0.1:41004#6"));
            flowRuleService.applyFlowRules(rm2_ip_port_h3("bmv2:127.0.0.1:41004#6"));

        } catch (Exception e) {
            System.out.println(e.toString());
        }



        log.info("Started", appId.id());
    }


    @Deactivate
    public void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);

        //TODO:删除我们自己添加的表！
        ApplicationId myAppId = coreService.registerApplication("org.onosproject.myfwd");
        flowRuleService.removeFlowRulesById(myAppId);


        packetService.removeProcessor(processor);
        topologyService.removeListener(topologyListener);
        processor = null;

        System.out.println("Goodbye FWD!");

        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
        requestIntercepts();
    }

    /**
     * Request packet in via packet service.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV6);
        if (ipv6Forwarding) {
            packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        } else {
            packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        }
    }

    /**
     * Cancel request for packet in via packet service.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Extracts properties from the component configuration context.
     *
     * @param context the component context
     */
    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();

        Boolean packetOutOnlyEnabled =
                Tools.isPropertyEnabled(properties, "packetOutOnly");
        if (packetOutOnlyEnabled == null) {
            log.info("Packet-out is not configured, " +
                    "using current value of {}", packetOutOnly);
        } else {
            packetOutOnly = packetOutOnlyEnabled;
            log.info("Configured. Packet-out only forwarding is {}",
                    packetOutOnly ? "enabled" : "disabled");
        }

        Boolean packetOutOfppTableEnabled =
                Tools.isPropertyEnabled(properties, "packetOutOfppTable");
        if (packetOutOfppTableEnabled == null) {
            log.info("OFPP_TABLE port is not configured, " +
                    "using current value of {}", packetOutOfppTable);
        } else {
            packetOutOfppTable = packetOutOfppTableEnabled;
            log.info("Configured. Forwarding using OFPP_TABLE port is {}",
                    packetOutOfppTable ? "enabled" : "disabled");
        }

        Boolean ipv6ForwardingEnabled =
                Tools.isPropertyEnabled(properties, "ipv6Forwarding");
        if (ipv6ForwardingEnabled == null) {
            log.info("IPv6 forwarding is not configured, " +
                    "using current value of {}", ipv6Forwarding);
        } else {
            ipv6Forwarding = ipv6ForwardingEnabled;
            log.info("Configured. IPv6 forwarding is {}",
                    ipv6Forwarding ? "enabled" : "disabled");
        }

        Boolean matchDstMacOnlyEnabled =
                Tools.isPropertyEnabled(properties, "matchDstMacOnly");
        if (matchDstMacOnlyEnabled == null) {
            log.info("Match Dst MAC is not configured, " +
                    "using current value of {}", matchDstMacOnly);
        } else {
            matchDstMacOnly = matchDstMacOnlyEnabled;
            log.info("Configured. Match Dst MAC Only is {}",
                    matchDstMacOnly ? "enabled" : "disabled");
        }

        Boolean matchVlanIdEnabled =
                Tools.isPropertyEnabled(properties, "matchVlanId");
        if (matchVlanIdEnabled == null) {
            log.info("Matching Vlan ID is not configured, " +
                    "using current value of {}", matchVlanId);
        } else {
            matchVlanId = matchVlanIdEnabled;
            log.info("Configured. Matching Vlan ID is {}",
                    matchVlanId ? "enabled" : "disabled");
        }

        Boolean matchIpv4AddressEnabled =
                Tools.isPropertyEnabled(properties, "matchIpv4Address");
        if (matchIpv4AddressEnabled == null) {
            log.info("Matching IPv4 Address is not configured, " +
                    "using current value of {}", matchIpv4Address);
        } else {
            matchIpv4Address = matchIpv4AddressEnabled;
            log.info("Configured. Matching IPv4 Addresses is {}",
                    matchIpv4Address ? "enabled" : "disabled");
        }

        Boolean matchIpv4DscpEnabled =
                Tools.isPropertyEnabled(properties, "matchIpv4Dscp");
        if (matchIpv4DscpEnabled == null) {
            log.info("Matching IPv4 DSCP and ECN is not configured, " +
                    "using current value of {}", matchIpv4Dscp);
        } else {
            matchIpv4Dscp = matchIpv4DscpEnabled;
            log.info("Configured. Matching IPv4 DSCP and ECN is {}",
                    matchIpv4Dscp ? "enabled" : "disabled");
        }

        Boolean matchIpv6AddressEnabled =
                Tools.isPropertyEnabled(properties, "matchIpv6Address");
        if (matchIpv6AddressEnabled == null) {
            log.info("Matching IPv6 Address is not configured, " +
                    "using current value of {}", matchIpv6Address);
        } else {
            matchIpv6Address = matchIpv6AddressEnabled;
            log.info("Configured. Matching IPv6 Addresses is {}",
                    matchIpv6Address ? "enabled" : "disabled");
        }

        Boolean matchIpv6FlowLabelEnabled =
                Tools.isPropertyEnabled(properties, "matchIpv6FlowLabel");
        if (matchIpv6FlowLabelEnabled == null) {
            log.info("Matching IPv6 FlowLabel is not configured, " +
                    "using current value of {}", matchIpv6FlowLabel);
        } else {
            matchIpv6FlowLabel = matchIpv6FlowLabelEnabled;
            log.info("Configured. Matching IPv6 FlowLabel is {}",
                    matchIpv6FlowLabel ? "enabled" : "disabled");
        }

        Boolean matchTcpUdpPortsEnabled =
                Tools.isPropertyEnabled(properties, "matchTcpUdpPorts");
        if (matchTcpUdpPortsEnabled == null) {
            log.info("Matching TCP/UDP fields is not configured, " +
                    "using current value of {}", matchTcpUdpPorts);
        } else {
            matchTcpUdpPorts = matchTcpUdpPortsEnabled;
            log.info("Configured. Matching TCP/UDP fields is {}",
                    matchTcpUdpPorts ? "enabled" : "disabled");
        }

        Boolean matchIcmpFieldsEnabled =
                Tools.isPropertyEnabled(properties, "matchIcmpFields");
        if (matchIcmpFieldsEnabled == null) {
            log.info("Matching ICMP (v4 and v6) fields is not configured, " +
                    "using current value of {}", matchIcmpFields);
        } else {
            matchIcmpFields = matchIcmpFieldsEnabled;
            log.info("Configured. Matching ICMP (v4 and v6) fields is {}",
                    matchIcmpFields ? "enabled" : "disabled");
        }

        Boolean ignoreIpv4McastPacketsEnabled =
                Tools.isPropertyEnabled(properties, "ignoreIpv4McastPackets");
        if (ignoreIpv4McastPacketsEnabled == null) {
            log.info("Ignore IPv4 multi-cast packet is not configured, " +
                    "using current value of {}", ignoreIpv4McastPackets);
        } else {
            ignoreIpv4McastPackets = ignoreIpv4McastPacketsEnabled;
            log.info("Configured. Ignore IPv4 multicast packets is {}",
                    ignoreIpv4McastPackets ? "enabled" : "disabled");
        }
        flowTimeout = Tools.getIntegerProperty(properties, "flowTimeout", DEFAULT_TIMEOUT);
        log.info("Configured. Flow Timeout is configured to {}", flowTimeout, " seconds");

        flowPriority = Tools.getIntegerProperty(properties, "flowPriority", DEFAULT_PRIORITY);
        log.info("Configured. Flow Priority is configured to {}", flowPriority);
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.

            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            // Skip IPv6 multicast packet when IPv6 forward is disabled.
            if (!ipv6Forwarding && isIpv6Multicast(ethPkt)) {
                return;
            }

            HostId id = HostId.hostId(ethPkt.getDestinationMAC());

            // Do not process link-local addresses in any way.
            if (id.mac().isLinkLocal()) {
                return;
            }

            // Do not process IPv4 multicast packets, let mfwd handle them
            if (ignoreIpv4McastPackets && ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (id.mac().isMulticast()) {
                    return;
                }
            }

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);
            if (dst == null) {
                flood(context);
                return;
            }

            // Are we on an edge switch that our destination is on? If so,
            // simply forward out to the destination and bail.
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(context, dst.location().port());
                }
                return;
            }

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                            pkt.receivedFrom().deviceId(),
                            dst.location().deviceId());
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
                flood(context);
                return;
            }

            // Otherwise, pick a path that does not lead back to where we
            // came from; if no such path, flood and bail.
            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                        pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context);
                return;
            }

            // Otherwise forward and be done with it.
            System.out.println("installRule");
            installRule(context, path.src().port());
        }

    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        Path lastPath = null;
        for (Path path : paths) {
            lastPath = path;
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return lastPath;
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber) {
        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        // If PacketOutOnly or ARP packet than forward directly to output port
        if (packetOutOnly || inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber);
            return;
        }

        //
        // If matchDstMacOnly
        //    Create flows matching dstMac only
        // Else
        //    Create flows with default matching and include configured fields
        //
        if (matchDstMacOnly) {
            selectorBuilder.matchEthDst(inPkt.getDestinationMAC());
        } else {
            selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                    .matchEthSrc(inPkt.getSourceMAC())
                    .matchEthDst(inPkt.getDestinationMAC());

            // If configured Match Vlan ID
            if (matchVlanId && inPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                selectorBuilder.matchVlanId(VlanId.vlanId(inPkt.getVlanID()));
            }

            //
            // If configured and EtherType is IPv4 - Match IPv4 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv4Address && inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();
                Ip4Prefix matchIp4SrcPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                Ip4Prefix.MAX_MASK_LENGTH);
                Ip4Prefix matchIp4DstPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                Ip4Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(matchIp4SrcPrefix)
                        .matchIPDst(matchIp4DstPrefix);

                if (matchIpv4Dscp) {
                    byte dscp = ipv4Packet.getDscp();
                    byte ecn = ipv4Packet.getEcn();
                    selectorBuilder.matchIPDscp(dscp).matchIPEcn(ecn);
                }

                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                    ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchIcmpType(icmpPacket.getIcmpType())
                            .matchIcmpCode(icmpPacket.getIcmpCode());
                }
            }

            //
            // If configured and EtherType is IPv6 - Match IPv6 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv6Address && inPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Packet = (IPv6) inPkt.getPayload();
                byte ipv6NextHeader = ipv6Packet.getNextHeader();
                Ip6Prefix matchIp6SrcPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getSourceAddress(),
                                Ip6Prefix.MAX_MASK_LENGTH);
                Ip6Prefix matchIp6DstPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getDestinationAddress(),
                                Ip6Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV6)
                        .matchIPv6Src(matchIp6SrcPrefix)
                        .matchIPv6Dst(matchIp6DstPrefix);

                if (matchIpv6FlowLabel) {
                    selectorBuilder.matchIPv6FlowLabel(ipv6Packet.getFlowLabel());
                }

                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv6NextHeader == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchIcmpv6Type(icmp6Packet.getIcmpType())
                            .matchIcmpv6Code(icmp6Packet.getIcmpCode());
                }
            }
        }
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                forwardingObjective);

        //
        // If packetOutOfppTable
        //  Send packet back to the OpenFlow pipeline to match installed flow
        // Else
        //  Send packet direction on the appropriate port
        //
        if (packetOutOfppTable) {
            packetOut(context, PortNumber.TABLE);
        } else {
            packetOut(context, portNumber);
        }
    }

    private class InternalTopologyListener implements TopologyListener {
        @Override
        public void event(TopologyEvent event) {
            List<Event> reasons = event.reasons();
            if (reasons != null) {
                reasons.forEach(re -> {
                    if (re instanceof LinkEvent) {
                        LinkEvent le = (LinkEvent) re;
                        if (le.type() == LinkEvent.Type.LINK_REMOVED) {
                            fixBlackhole(le.subject().src());
                        }
                    }
                });
            }
        }
    }

    private void fixBlackhole(ConnectPoint egress) {
        Set<FlowEntry> rules = getFlowRulesFrom(egress);
        Set<SrcDstPair> pairs = findSrcDstPairs(rules);

        Map<DeviceId, Set<Path>> srcPaths = new HashMap<>();

        for (SrcDstPair sd : pairs) {
            // get the edge deviceID for the src host
            Host srcHost = hostService.getHost(HostId.hostId(sd.src));
            Host dstHost = hostService.getHost(HostId.hostId(sd.dst));
            if (srcHost != null && dstHost != null) {
                DeviceId srcId = srcHost.location().deviceId();
                DeviceId dstId = dstHost.location().deviceId();
                log.trace("SRC ID is " + srcId + ", DST ID is " + dstId);

                cleanFlowRules(sd, egress.deviceId());

                Set<Path> shortestPaths = srcPaths.get(srcId);
                if (shortestPaths == null) {
                    shortestPaths = topologyService.getPaths(topologyService.currentTopology(),
                            egress.deviceId(), srcId);
                    srcPaths.put(srcId, shortestPaths);
                }
                backTrackBadNodes(shortestPaths, dstId, sd);
            }
        }
    }

    // Backtracks from link down event to remove flows that lead to blackhole
    private void backTrackBadNodes(Set<Path> shortestPaths, DeviceId dstId, SrcDstPair sd) {
        for (Path p : shortestPaths) {
            List<Link> pathLinks = p.links();
            for (int i = 0; i < pathLinks.size(); i = i + 1) {
                Link curLink = pathLinks.get(i);
                DeviceId curDevice = curLink.src().deviceId();

                // skipping the first link because this link's src has already been pruned beforehand
                if (i != 0) {
                    cleanFlowRules(sd, curDevice);
                }

                Set<Path> pathsFromCurDevice =
                        topologyService.getPaths(topologyService.currentTopology(),
                                curDevice, dstId);
                if (pickForwardPathIfPossible(pathsFromCurDevice, curLink.src().port()) != null) {
                    break;
                } else {
                    if (i + 1 == pathLinks.size()) {
                        cleanFlowRules(sd, curLink.dst().deviceId());
                    }
                }
            }
        }
    }

    // Removes flow rules off specified device with specific SrcDstPair
    private void cleanFlowRules(SrcDstPair pair, DeviceId id) {
        log.trace("Searching for flow rules to remove from: " + id);
        log.trace("Removing flows w/ SRC=" + pair.src + ", DST=" + pair.dst);
        for (FlowEntry r : flowRuleService.getFlowEntries(id)) {
            boolean matchesSrc = false, matchesDst = false;
            for (Instruction i : r.treatment().allInstructions()) {
                if (i.type() == Instruction.Type.OUTPUT) {
                    // if the flow has matching src and dst
                    for (Criterion cr : r.selector().criteria()) {
                        if (cr.type() == Criterion.Type.ETH_DST) {
                            if (((EthCriterion) cr).mac().equals(pair.dst)) {
                                matchesDst = true;
                            }
                        } else if (cr.type() == Criterion.Type.ETH_SRC) {
                            if (((EthCriterion) cr).mac().equals(pair.src)) {
                                matchesSrc = true;
                            }
                        }
                    }
                }
            }
            if (matchesDst && matchesSrc) {
                log.trace("Removed flow rule from device: " + id);
                flowRuleService.removeFlowRules((FlowRule) r);
            }
        }

    }

    // Returns a set of src/dst MAC pairs extracted from the specified set of flow entries
    private Set<SrcDstPair> findSrcDstPairs(Set<FlowEntry> rules) {
        ImmutableSet.Builder<SrcDstPair> builder = ImmutableSet.builder();
        for (FlowEntry r : rules) {
            MacAddress src = null, dst = null;
            for (Criterion cr : r.selector().criteria()) {
                if (cr.type() == Criterion.Type.ETH_DST) {
                    dst = ((EthCriterion) cr).mac();
                } else if (cr.type() == Criterion.Type.ETH_SRC) {
                    src = ((EthCriterion) cr).mac();
                }
            }
            builder.add(new SrcDstPair(src, dst));
        }
        return builder.build();
    }

    // Returns set of flow entries which were created by this application and
    // which egress from the specified connection port
    private Set<FlowEntry> getFlowRulesFrom(ConnectPoint egress) {
        ImmutableSet.Builder<FlowEntry> builder = ImmutableSet.builder();
        flowRuleService.getFlowEntries(egress.deviceId()).forEach(r -> {
            if (r.appId() == appId.id()) {
                r.treatment().allInstructions().forEach(i -> {
                    if (i.type() == Instruction.Type.OUTPUT) {
                        if (((Instructions.OutputInstruction) i).port().equals(egress.port())) {
                            builder.add(r);
                        }
                    }
                });
            }
        });

        return builder.build();
    }

    // Wrapper class for a source and destination pair of MAC addresses
    private final class SrcDstPair {
        final MacAddress src;
        final MacAddress dst;

        private SrcDstPair(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            SrcDstPair that = (SrcDstPair) o;
            return Objects.equals(src, that.src) &&
                    Objects.equals(dst, that.dst);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }
    }
}

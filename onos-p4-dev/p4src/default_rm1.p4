/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//TODO:RM
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

//get包头
header_type get_t {
    fields {
        version_type : 8;
	ttl : 8;
	total_len : 16;
	port_no1 :16;
	port_no2 :16;
	minpid :16;
	pids_o :8;
	res : 8;
	mtu : 16;
	checksum :16;
	//nid_s :128;
	//l_sid :160;
	sid :288;
	nid_c :128;
	mac :32;
	offset :32;
	len :32;
	pid1 :32;
    }
}



parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

// 定义一个get包头
header get_t get;

parser parse_ipv4 {
    extract(ipv4);
    return parse_get;
}
//解析get包
parser parse_get {
    extract(get);
    return ingress;
}

action _drop() {
    drop();
}

//在定义的元数据中增加flag,nid128bit不可用
header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
	nid : 132;
	flag : 8;

    }
}

metadata routing_metadata_t routing_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}
//sid_flag
action set_flag(flag) {
    modify_field(routing_metadata.flag, flag);
}
//在原本table0位置添加的空表，没有实际内容，是为了错开不显示的table0。
table empty {
    reads {
        get.sid: exact;
    }
    actions {
        set_flag;
        _drop;
    }
    size: 256;
}
//table0 sid_flag {
table sid_flag {
    reads {
        get.sid: exact;
    }
    actions {
        set_flag;
        _drop;
    }
    size: 256;
}
//sid_nid_ip
action set_nid_ip(nid,ip) {
    modify_field(routing_metadata.nid, nid);
	modify_field(ipv4.dstAddr, ip);
}

//table1 sid_nid_ip {
table sid_nid_ip {
    reads {
        get.sid: exact;
    }
    actions {
        set_nid_ip;
        _drop;
    }
    size: 1024;
}
//sid_pid_ip
action set_pid_ip(pid,ip) {
        modify_field(get.pid1,pid);
	add_to_field(get.pids_o, 1);
	modify_field(ipv4.dstAddr, ip);
}


//table2 sid_pid_ip {
table sid_pid_ip{
    reads {
        get.sid: exact;
    }
    actions {
        set_pid_ip;
        _drop;
    }
    size: 1024;
}

action set_egress_port(port) {
    modify_field(standard_metadata.egress_spec, port);
}

//table3 ip_port {
table ip_port{
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_egress_port;
        _drop;
    }
    size: 1024;
}

/*
control ingress {
//执行表：sid_flag表确定域内外，域内走nid,域外走pid
	
	apply(sid_flag);
	if(routing_metadata.flag==0)
	{
		apply(sid_nid_ip);
	}
	else
	{
		apply(sid_pid_ip);
	}
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_lpm);
        apply(forward);
    }
}

control egress {
    apply(send_frame);
    apply(ip_port);
}
*/

//注释掉IP-mac，改为IP-port	
control ingress {
//执行表：sid_flag表确定域内外，域内走nid,域外走pid
	
	apply(sid_flag);
	if(routing_metadata.flag==0)
	{
		apply(sid_nid_ip);
	}
	else
	{
		apply(sid_pid_ip);
	}
	 apply(ip_port);
         //apply(empty);
}

control egress {
   
}



/*
#include "include/defines.p4"
#include "include/headers.p4"
#include "include/parser.p4"
#include "include/actions.p4"
#include "include/port_counters.p4"

//在定义的元数据中增加flag,nid128bit不可用
header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
	sid : 160;

    }
}

metadata routing_metadata_t routing_metadata;

table table0 {
    reads {
       //standard_metadata.ingress_port : ternary;
       //ethernet.dstAddr : ternary;
       //ethernet.srcAddr : ternary;
       //ethernet.etherType : ternary;
       //l add it
       //ipv4.dstAddr : lpm;
	ipv4.dstAddr : lpm;
    }
    actions {
        set_egress_port;
        send_to_cpu;
        _drop;
    }
    support_timeout: true;
}


table table1 {
    reads {
       //standard_metadata.ingress_port : ternary;
       //ethernet.dstAddr : ternary;
       //ethernet.srcAddr : ternary;
       //ethernet.etherType : ternary;
       //l add it
       //ipv4.dstAddr : lpm;
	routing_metadata.sid : exact;
    }
    actions {
        set_egress_port;
        send_to_cpu;
        _drop;
    }
    support_timeout: true;
}

table table2 {
    reads {
       //standard_metadata.ingress_port : ternary;
       //ethernet.dstAddr : ternary;
       //ethernet.srcAddr : ternary;
       //ethernet.etherType : ternary;
       //l add it
       //ipv4.dstAddr : lpm;
	routing_metadata.sid : lpm;
    }
    actions {
        set_egress_port;
        send_to_cpu;
        _drop;
    }
    support_timeout: true;
}

table table3 {
    reads {
       //standard_metadata.ingress_port : ternary;
       //ethernet.dstAddr : ternary;
       //ethernet.srcAddr : ternary;
       //ethernet.etherType : ternary;
       //l add it
       //ipv4.dstAddr : lpm;
	ipv4.dstAddr : lpm;
    }
    actions {
        set_egress_port;
        send_to_cpu;
        _drop;
    }
    support_timeout: true;
}


counter table0_counter {
    type: packets;
    direct: table0;
    min_width : 32;
}

control ingress {
    apply(table0);
    apply(table1);
    apply(table2);
    apply(table3);
   // process_port_counters();
}

*/

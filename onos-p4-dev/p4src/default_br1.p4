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

//TODO:BR
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

//data包头
header_type data_t {
    fields {
        version_type : 8;
		ttl : 8;
		total_len : 16;
		port_no1 :16;
		port_no2 :16;
		minpid :16;
		pids_o :8;
		res : 8;
		pid_index :8;
		reserved :8;
		checksum :16;
		//nid_s :128;
		//l_sid :160;	
		sid :288;
		nid_c :120;
		nid_c_pad:8;
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

// 定义一个get,data包头
header get_t get;
header data_t data;
//根据ipv4.protocol确定下一个包的类型,0xa0=160为get包
#define IPTYPE_COLOR_GET 0xa0
#define IPTYPE_COLOR_DATA 0xa1

//依据对包头的判断执行不同的解析包
parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
    IPTYPE_COLOR_GET : parse_get;
	IPTYPE_COLOR_DATA : parse_data;
        default: ingress;
    }
}
//解析get包
parser parse_get {
    extract(get);
    return ingress;
}
//解析data包
parser parse_data {
    extract(data);
    return ingress;
}

action _drop() {
    drop();
}

//在定义的元数据中增加flag,nid128bit不可用
header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;

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



action set_ip(ip) {
	modify_field(ipv4.dstAddr, ip);
}
//在原本table0位置添加的空表，没有实际内容，是为了错开不显示的table0。
table empty1 {
 reads {
        get.pid1: exact;
    }
    actions {
        set_ip;
        _drop;
    }
    size: 1024;
}
table empty2 {
 reads {
        get.pid1: exact;
    }
    actions {
        set_ip;
        _drop;
    }
    size: 1024;
}


//table0: get_inter_pid_ip
table get_inter_pid_ip {
    reads {
        get.pid1: exact;
    }
    actions {
        set_ip;
        _drop;
    }
    size: 1024;
}

//table1: get_to_rm 给定一个恒成立的匹配域match
table get_to_rm{
    reads {
        get.version_type: exact;
    }
    actions {
       set_ip;
        _drop;
    }
    size: 1024;
}

//table5: data_inter_pid_ip
table data_inter_pid_ip {
    reads {
        data.pid1: exact;
    }
    actions {
		//We subtract the pids_o only when the table does the actions.
        set_ip;
        _drop;
    }
    size: 1024;
}

//table3: data_nid_c_ip
table data_nid_c_ip {
    reads {
        data.nid_c: exact;
    }
    actions {
        set_ip;
        _drop;
    }
    size: 1024;
}
//table4: data_intra_pid_ip
table data_intra_pid_ip {
    reads {
        data.pid1: exact;
    }
    actions {
       set_ip;
        _drop;
    }
    size: 1024;
}

action  set_pids_o() {
	add_to_field(data.pids_o, -1);
}

//table2: data_pids_o_subtract 给定一个恒成立的匹配域match
table data_pids_o_subtract {
    reads {
         data.version_type: exact;
    }
    actions {
        set_pids_o;
        _drop;
    }
    size: 1024;
}

action set_egress_port(port) {
    modify_field(standard_metadata.egress_spec, port);
}
//table6: ip_port {
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
table some_tables{
    reads {
        get.version_type: exact;
    }
    actions {
        set_ip;
        _drop;
    }
    size: 1024;
}
*/

//执行表：如果是get包，先确定从ＲＭ来或从BR来，之后由pid确定目的ip或直接交付ＲＭ
#define intra_domain_port1 1
#define inter_domain_port1 2
control ingress {
    if(ipv4.protocol==IPTYPE_COLOR_GET)
{
    if(standard_metadata.ingress_port==intra_domain_port1)
    {
       apply(get_inter_pid_ip);
    }
    else if(standard_metadata.ingress_port==inter_domain_port1)
    { 
        apply(get_to_rm);
    }
}

//若为data包，则先确定是从同一域的BR还是另外一域的对端BR来，对端另一个域BR来的包要判断是否在本域，在本域查询nid_c,不在给BR,
//同一域BR来的包根据pid选路送到另一个域BR去
    else if(ipv4.protocol==IPTYPE_COLOR_DATA)
    {
	if(standard_metadata.ingress_port==inter_domain_port1)
        {    
			apply(data_pids_o_subtract);
            if(data.pids_o==0)
            {
                apply(data_nid_c_ip);    
            }  
            else if(data.pids_o==1) 
            {
			//查询的pid从pid2变成pid1，将data包从本域BR从给另一个BR             
                apply(data_intra_pid_ip); 
            }	
        } 
        else
        { 
            apply(data_inter_pid_ip);
        }

	}
/*
//#定义RM和另一个域的对端BR的ip
#define RM_ip 0x0a000001
#define outside_BR_ip 0x0a000003
control ingress {
//执行表：如果是get包，先确定从ＲＭ来或从BR来，之后由pid确定目的ip或直接交付ＲＭ
    if(ipv4.protocol==IPTYPE_COLOR_GET)
	{
        if(ipv4.srcAddr== RM_ip)
        {
            apply(get_inter_pid_ip);
        }
        else if(ipv4.srcAddr==outside_BR_ip)
        {
            apply(get_to_rm);
        }
	}

若为data包，则先确定是从同一域的BR还是另外一域的对端BR来，对端另一个域BR来的包要判断是否在本域，在本域查询nid_c,不在给BR,
同一域BR来的包根据pid选路送到另一个域BR去
    else if(ipv4.protocol==IPTYPE_COLOR_DATA)
    {
	if(ipv4.srcAddr==outside_BR_ip)
        {    
			apply(data_pids_o_subtract);
            if(data.pids_o==0)
            {
                apply(data_nid_c_ip);    
            }  
            else if(data.pids_o==1) 
            {
			//查询的pid从pid2变成pid1，将data包从本域BR从给另一个BR             
                apply(data_intra_pid_ip); 
            }	
        } 
        else
        { 
            apply(data_inter_pid_ip);
        }

	}
  */
  
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ip_port);
        //apply(forward);
	//apply (empty1);
	//apply (empty2);
    }
}

control egress {
    //apply(send_frame);
}



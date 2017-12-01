#include "include/defines.p4"
#include "include/headers.p4"
#include "include/parser.p4"
#include "include/actions.p4"
#include "include/port_counters.p4"

table fwd {
    reads {
        standard_metadata.ingress_port : ternary;
        ethernet.dstAddr : ternary;
        ethernet.srcAddr : ternary;
        ethernet.etherType : ternary;
        ipv4.dstAddr : ternary;
    }
    actions {
        set_egress_port;
        send_to_cpu;
        _drop;
    }
    //support_timeout: false;
}

counter table0_counter {
    type: packets;
    direct: fwd;
    min_width : 32;
}

table table1 {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_egress_port;
        send_to_cpu;
        _drop;
    }
    //support_timeout: false;
}

control ingress {
    apply(fwd);
    apply(table1);
    //process_port_counters();
}

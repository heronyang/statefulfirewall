/*
 * statefulipfilter.{cc,hh} -- Stateful IP-packet filter
 *
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>


#if CLICK_LINUXMODULE
# include <linux/in.h>
#else
# include <netinet/in.h>
#endif

#include <arpa/inet.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include "statefulfirewall.hh"

#define BYTE_LENGTH 8
#define LINE_LENGTH 200
#define IP_LENGTH 20

CLICK_DECLS
/**
 * Helper Functions
 */
Policy policy_builder(char *line) {

    stringstream stream_line(line);

    string sourceip = "", destip = "";
    int sourceport, destport;
    int proto;
    int action;

    stream_line >> sourceip >> sourceport >> destip >> destport >> proto >> action;

    String sourceip_str(sourceip.c_str());
    String destip_str(destip.c_str());

    Policy policy(sourceip_str, destip_str, sourceport, destport, proto, action);

    return policy;
}

/**
 * Connection Class
 */
Connection::Connection(String s, String d, int sp, int dp, int pr, bool fwdflag) {
    sourceip = s;
    destip = d;
    sourceport = sp;
    destport = dp;
    proto = pr;
    isfw = fwdflag;
}
Connection::Connection() { }
Connection::~Connection() { }

/* Can be useful for debugging*/
void
Connection::print() const {
    cout << "[Connection] print" << endl;
    cout << "sourceip=" << sourceip.c_str() << "\t";
    cout << "destip=" << destip.c_str() << "\t";
    cout << "sourceport=" << sourceport << "\t";
    cout << "destport=" << destport << "\t";
    cout << "proto=" << proto << "\t";
    cout << "isfw=" << isfw << endl;
}

/* Overlaod == operator to check if two Connection objects are equal.
 * You may or may not want to ignore the isfw flag for comparison depending on your implementation.
 * Return true if equal. false otherwise. */
bool
Connection::operator==(const Connection &other) const {
    return (compare(other) == 1);
}

/* Compare two connections to determine the sequence in map. */
int
Connection::compare(const Connection other) const {

    bool s1, s2, s3, s4, s5;

    s1 = (sourceip.compare(other.sourceip)==0);
    s2 = (destip.compare(other.destip)==0);
    s3 = (sourceport == other.sourceport);
    s4 = (destport == other.destport);
    s5 = (proto == other.proto);

    if( s1 && s2 && s3 && s4 && s5 )  return 1;
    return -1;
}

/**
 * Policy
 */
Policy::Policy(String s, String d, int sp, int dp, int p, int act) {
    sourceip = s;
    destip = d;
    sourceport = sp;
    destport = dp;
    proto = p;
    action = act;
}
Policy::~Policy() { }

void
Policy::print() const {
    cout << "sourceip: " << sourceip.c_str() << ", ";
    cout << "destip: " << destip.c_str() << ", ";
    cout << "sourceport: " << sourceport << ", ";
    cout << "destport: " << destport << ", ";
    cout << "proto: " << proto << ", ";
    cout << "action: " << action << endl;
}

Connection
Policy::getConnection() {
    Connection *con;
    if( sourceip.compare(destip) < 0 ) {
        con = new Connection(sourceip, destip, sourceport, destport, proto, false);
    } else {
        con = new Connection(destip, sourceip, destport, sourceport, proto, true);
    }
    return *con;
}

/**
 * StatefulFirewall Class
 */
StatefulFirewall::StatefulFirewall() {
    no = 1;
}

StatefulFirewall::~StatefulFirewall() {
    /*
    cout << "print out all policies for fun" << endl;
    for(vector<Policy>::iterator it = list_of_policies.begin();
            it != list_of_policies.end(); ++it) {
        it->print();
    }
    */
}

int
StatefulFirewall::read_policy_config(String filepath) {

    char line[LINE_LENGTH];
    ifstream policy_file;
    policy_file.open(filepath.c_str());
    if (policy_file.is_open()) {
        while (!policy_file.eof()) {
            policy_file.getline(line, sizeof(line));
            if (line[0] == '#' || strlen(line)<=1) continue;
            Policy new_policy = policy_builder(line);
            list_of_policies.push_back(new_policy);
            new_policy.print();
        }
    } else {
        return 1;
    }

    policy_file.close();
    return 0;

}

int
StatefulFirewall::configure(Vector<String> &conf, ErrorHandler *errh) {

    String filepath = "";
    if (Args(conf, this, errh)
            .read_mp("POLICYFILE", filepath)
            .read_mp("DEFAULT", default_val)
            .complete() < 0) {
        return -1;
    }

    if (default_val != 1 && default_val != 0) {
        return errh->error("DEFAULT must be 0 or 1");
    }

    if (read_policy_config(filepath) != 0) {
        return errh->error("POLICYFILE file read error");
    }

    return 0;

}

bool
StatefulFirewall::check_if_new_connection(const Packet *packet) {
    const click_tcp *tcp_header = packet->tcp_header();
    // bool syn_flag = (tcp_header->th_flags & TH_RST);
    Connection con = get_canonicalized_connection(packet);
    for (map<Connection, int>::iterator it=Connections.begin();
            it!=Connections.end(); ++it) {
        if (it->first == con) {
            return false;
        }
    }
    // return (Connections.find(con) == Connections.end());
    return true;
}

bool
StatefulFirewall::check_if_connection_reset(const Packet *packet) {
    const click_tcp *tcp_header = packet->tcp_header();
    return tcp_header->th_flags & TH_RST;
}

void
StatefulFirewall::add_connection(Connection &c, int action) {
    Connections.insert(pair<Connection, int>(c, action));
}

void
StatefulFirewall::delete_connection(Connection &c) {
    cout << "delete connection (no:" << no << ")" << endl;
    c.print();
    for (map<Connection, int>::iterator it=Connections.begin();
            it!=Connections.end(); ++it) {
        if (it->first == c) {
            cout << "earse: " << Connections.erase(it->first) << endl;
        }
    }
}

Connection
StatefulFirewall::get_canonicalized_connection(const Packet *packet) {

    const click_ip *ip_header = packet->ip_header();
    const click_tcp *tcp_header = packet->tcp_header();

    // IP
    struct in_addr ip_src = ip_header->ip_src;
    struct in_addr ip_dst = ip_header->ip_dst;
    int proto = (int)ip_header->ip_p;

    String ip_src_str(inet_ntoa(ip_src));
    String ip_dst_str(inet_ntoa(ip_dst));

    // TCP
    int sp = ((int)tcp_header->th_sport) >> BYTE_LENGTH;
    int dp = ((int)tcp_header->th_dport) >> BYTE_LENGTH;

    Connection *new_connection;
    if( ip_src_str.compare(ip_dst_str) < 0 ) {
        new_connection = new Connection(ip_src_str, ip_dst_str,
                sp, dp, proto, false);
    } else {
        new_connection = new Connection(ip_dst_str, ip_src_str,
                dp, sp, proto, true);
    }

    return *new_connection;

}

int
StatefulFirewall::filter_packet(const Packet *packet) {

    Connection con = get_canonicalized_connection(packet);

    if( check_if_new_connection(packet) ) {

        cout << "new connection (no:" << no << ")" << endl;
        con.print();

        int action = apply_policy(con);

        if( check_if_connection_reset(packet) ) {
            delete_connection(con);
        } else {
            add_connection(con, action);
        }

        return action;
    }

    int res = 0;
    for (map<Connection, int>::iterator it=Connections.begin();
            it!=Connections.end(); ++it) {
        if (it->first == con) {
            res = it->second;
        }
    }
    if( check_if_connection_reset(packet) ) {
        delete_connection(con);
    }
    return res;

}

int
StatefulFirewall::apply_policy(Connection con) {
    for(vector<Policy>::iterator it = list_of_policies.begin();
            it != list_of_policies.end(); ++it) {
        Policy p = *it;
        Connection pc = p.getConnection();
        if( pc == con && (pc.is_forward() == con.is_forward()) ) {
            return p.getAction();
        }
    }
    return default_val;
}

void
StatefulFirewall::push(int port, Packet *packet) {

    int p = (filter_packet(packet))? 1 : port;
    output(p).push(packet);
    /*
    cout << "==== pop all connection for fun" << endl;
    for (map<Connection, int>::iterator it=Connections.begin();
            it!=Connections.end(); ++it) {
        it->first.print();
    }
    cout << "====" << endl;
    */
    no ++;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StatefulFirewall)

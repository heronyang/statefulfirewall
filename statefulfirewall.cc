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
    policy.print();

    return policy;
}

/**
 * Connection Class
 */
Connection::Connection(String s, String d, int sp, int dp, int pr, bool fwdflag) {
    //Add your implementation here.
    cout << "[Connection] Connection (...)" << endl;

    sourceip = s;
    destip = d;
    sourceport = sp;
    destport = dp;
    proto = pr;
    isfw = fwdflag;

    print();
}
Connection::Connection() {
    cout << "[Connection] Connection" << endl;
}
Connection::~Connection() {
    cout << "[Connection] ~Connection" << endl;
}

/* Can be useful for debugging*/
void
Connection::print() const {
    //Add your implementation here.
    cout << "[Connection] port" << endl;
    cout << "sourceip=" << sourceip << "\t";
    cout << "destip=" << destip << "\t";
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
    //Add your implementation here.
    cout << "[Connection] operator==" << endl;
}

/*Compare two connections to determine the sequence in map.*/
int
Connection::compare(const Connection other) const {
    //Add your implementation here.
    cout << "[Connection] compare" << endl;
}

/**
 * Policy
 */
Policy::Policy(String s, String d, int sp, int dp, int p, int act) {
    //Add your implementation here.
    cout << "[Policy] Policy" << endl;
    sourceip = s;
    destip = d;
    sourceport = sp;
    destport = dp;
    proto = p;
    action = act;
}
Policy::~Policy() {
    cout << "[Policy] ~Policy" << endl;
}

void
Policy::print() const {
    cout << "sourceip: " << sourceip.c_str() << ", ";
    cout << "destip: " << destip.c_str() << ", ";
    cout << "sourceport: " << sourceport << ", ";
    cout << "destport: " << destport << ", ";
    cout << "proto: " << proto << ", ";
    cout << "action: " << action << endl;
}

/* Return a Connection object representing policy */
Connection
Policy::getConnection() {
    cout << "[Policy] getConnection" << endl;
}


/**
 * StatefulFirewall Class
 */
StatefulFirewall::StatefulFirewall() {
    cout << "[StatefulFirewall] StatefulFirewall" << endl;
}

StatefulFirewall::~StatefulFirewall() {
    cout << "[StatefulFirewall] ~StatefulFirewall" << endl;
    cout << "print out all policies for fun" << endl;
    for(vector<Policy>::iterator it = list_of_policies.begin();
            it != list_of_policies.end(); ++it) {
        it->print();
    }
}

/* Take the configuration paramenters as input corresponding to
 * POLICYFILE and DEFAULT where
 * POLICYFILE : Path of policy file
 * DEFAULT : Default action (0/1)
 *
 * Example: StatefulFirewall(POLICYFILE "sample_policy.1", DEFAULT 1);
 *
 * Hint: Refer to configure methods in other elemsnts.*/
int
StatefulFirewall::configure(Vector<String> &conf, ErrorHandler *errh) {

    cout << "[StatefulFirewall] configure" << endl;

    String filepath = "";
    int default_val = 0;
    if (Args(conf, this, errh)
            .read_mp("POLICYFILE", filepath)
            .read_mp("DEFAULT", default_val)
            .complete() < 0) {
        return -1;
    }

    if (default_val != 1 && default_val != 0) {
	    return errh->error("DEFAULT must be 0 or 1");
    }

    char line[LINE_LENGTH];
    ifstream policy_file;
    policy_file.open(filepath.c_str());
    if (policy_file.is_open()) {
        while (!policy_file.eof()) {
            policy_file.getline(line, sizeof(line));
            if (line[0] == '#') continue;
            Policy new_policy = policy_builder(line);
            list_of_policies.push_back(new_policy);
            new_policy.print();
        }
    } else {
	    return errh->error("POLICYFILE file read error");
    }
    policy_file.close();


    cout << "POLICYFILE: " << filepath.c_str() << endl;
    cout << "DEFAULT: " << default_val << endl;
    return 0;

}

void
StatefulFirewall::push(int port, Packet *packet) {

    cout << "[StatefulFirewall] push" << endl;

    const click_ip *ip_header = packet->ip_header();
    const click_tcp *tcp_header = packet->tcp_header();

    // IP
    struct in_addr ip_src = ip_header->ip_src;
    struct in_addr ip_dst = ip_header->ip_dst;

    String ip_src_str(inet_ntoa(ip_src));
    String ip_dst_str(inet_ntoa(ip_dst));

    // TCP
    int sp = ((int)tcp_header->th_sport) >> BYTE_LENGTH;
    int dp = ((int)tcp_header->th_dport) >> BYTE_LENGTH;

    // got it, here
    cout << "ip_src_str = " << ip_src_str.c_str() << endl;
    cout << "ip_dst_str = " << ip_dst_str.c_str() << endl;
    cout << "source port = " << sp << endl;
    cout << "destination port = " << dp << endl;

}

CLICK_ENDDECLS
EXPORT_ELEMENT(StatefulFirewall)

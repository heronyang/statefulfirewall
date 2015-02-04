/*
 * statefulipfilter.{cc,hh} -- Stateful IP-packet filter
 *
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <iostream>
#include <fstream>

#include "statefulfirewall.hh"

/* Add header files as required*/
CLICK_DECLS

/**
 * Connection Class
 */
Connection::Connection(String s, String d, int sp, int dp, int pr, bool fwdflag) {
    //Add your implementation here.
    cout << "[Connection] Connection" << endl;

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
}

/*Compare two connections to determine the sequence in map.*/
int
Connection::compare(const Connection other) const {
    //Add your implementation here.
}

/**
 * Policy
 */
Policy::Policy(String s, String d, int sp, int dp, int p, int act) {
    //Add your implementation here.
    cout << "[Policy] Policy" << endl;
    ofstream myfile;
    myfile.open ("/tmp/example.txt");
    myfile << "Writing this to a file.\n";
    myfile.close();
}
Policy::~Policy() {
    cout << "[Policy] ~Policy" << endl;
}
/* Return a Connection object representing policy */
Connection
Policy::getConnection() {
}


/**
 * StatefulFirewall Class
 */
StatefulFirewall::StatefulFirewall() {
}

StatefulFirewall::~StatefulFirewall() {
}

/* Take the configuration paramenters as input corresponding to
 * POLICYFILE and DEFAULT where
 * POLICYFILE : Path of policy file
 * DEFAULT : Default action (0/1)
 *
 * Hint: Refer to configure methods in other elemsnts.*/
int
StatefulFirewall::configure(Vector<String> &conf, ErrorHandler *errh) {
}

void
StatefulFirewall::push(int port, Packet *) {
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StatefulFirewall)

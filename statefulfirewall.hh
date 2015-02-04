#ifndef CLICK_STATEFULFIREWALL_HH
#define CLICK_STATEFULFIREWALL_HH
#include <click/element.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <map>
#include <iostream>
#include <vector>
CLICK_DECLS

using namespace std;

class Connection {

private:
	String sourceip;
	String destip;
	int sourceport;
	int destport;
	int proto;
	bool isfw; //true if forward connection. false if reverse connection.

public:
	Connection(String s, String d, int sp, int dp, int pr, bool fwdflag);
	Connection();
	~Connection();

	void print() const;
    bool operator==(const Connection &other) const;
    int compare(const Connection other) const;
    bool is_forward() { return isfw; }  // Return value of isfw
};

class Policy {

private:
	String sourceip;
	String destip;
	int sourceport;
	int destport;
	int proto;
	int action;

public:
	Policy(String s, String d, int sp, int dp, int p, int act);
	~Policy();

	void print() const;
	Connection getConnection();
	int getAction() { return action; } // Return action for this Policy
};

struct cmp_connection {
   bool operator()(Connection const a, Connection const b) {
      return a.compare(b) < 0;
   }
};

class StatefulFirewall : public Element {

private:
	std::map<Connection, int, cmp_connection> Connections; //Map of connections to their actions.
	std::vector<Policy> list_of_policies;

public:

	StatefulFirewall();
    ~StatefulFirewall();

    int configure(Vector<String> &conf, ErrorHandler *errh);

    const char *class_name() const		{ return "StatefulFirewall"; }
    const char *port_count() const		{ return "1/2"; }
    const char *processing() const		{ return PUSH; }
    // this element does not need AlignmentInfo; override Classifier's "A" flag
    const char *flags() const			{ return ""; }

    /* return true if Packet represents a new connection
     * i.e., check if the connection exists in the map.
     * You can also check the SYN flag in the header to be sure.
     * else return false.
     * Hint: Check the connection ID database.
     */
    bool check_if_new_connection(const Packet *);

    /*Check if the packet represent Connection reset
     * i.e., if the RST flag is set in the header.
     * Return true if connection reset
     * else return false.*/
    bool check_if_connection_reset(const Packet *);

    /* Add a new connection to the map along with its action.*/
    void add_connection(Connection &c, int action);

    /* Delete the connection from map*/
    void delete_connection(Connection &c);

    /* Create a new connection object for Packet.
     * Make sure you canonicalize the source and destination ip address and port number.
     * i.e, make the source less than the destination and
     * update isfw to false if you have to swap source and destination.
     * return NULL on error. */
    Connection get_canonicalized_connection(const Packet *);

    /* Read policy from a config file whose path is passed as parameter.
     * Update the policy database.
     * Policy config file structure would be space separated list of
     * <source_ip source_port destination_ip destination_port protocol action>
     * Add Policy objects to the list_of_policies
     * */
    int read_policy_config(String);

    /* Convert the integer ip address to string in dotted format.
     * Store the string in s.
     *
     * Hint: ntohl could be useful.*/
    void dotted_addr(const uint32_t *addr, char *s);


   /* Check if Packet belongs to new connection.
    * If new connection, apply the policy on this packet
    * and add the result to the connection map.
    * Else return the action in map.
    * If Packet indicates connection reset,
    * delete the connection from connection map.
    *
    * Return 1 if packet is allowed to pass
    * Return 0 if packet is to be discarded
    */
    int filter_packet(const Packet *);

    /* Push valid traffic on port 1
    * Push discarded traffic on port 0*/
    void push(int port, Packet *);

    /*The default action configured for the firewall.*/
    int DEFAULTACTION;
};

CLICK_ENDDECLS
#endif

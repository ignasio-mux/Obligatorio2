/*-----------------------------------------------------------------------------
 * file:  sr_rip.h
 * date:  Mon Sep 22 23:15:59 GMT-3 2025 
 * Authors: Santiago Freire
 * Contact: sfreire@fing.edu.uy
 *
 * Description:
 *
 * Data structures and methods for handling RIP protocol
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_RIP_H
#define SR_RIP_H

#define RIP_IP 0xE0000009  /* 224.0.0.9 - RIPv2 multicast address */
#define RIP_PORT 520
#define RIP_COMMAND_REQUEST 1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION 2
#define INFINITY 16
#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 60
#define RIP_GARBAGE_COLLECTION_SEC 40

struct sr_rip_subsys
{
    pthread_t thread;
    pthread_mutex_t lock;
};

typedef struct sr_rip_entry_t { /* Entrada RIP V2 - ver sec 4.0 RFC 2453 */
    uint16_t family_identifier;
    uint16_t route_tag;
    uint32_t ip;
    uint32_t mask;
    uint32_t next_hop;
    uint32_t metric;
} __attribute__ ((packed)) sr_rip_entry_t;

typedef struct sr_rip_packet_t { /* Paquete RIP */
    uint8_t command; /* Tipo de mensaje RIP */
    uint8_t version; /* Versión de RIP */
    uint16_t zero; /* Tiene que ser cero */
    sr_rip_entry_t entries[]; /* flexible array de entradas RIP */

} __attribute__ ((packed)) sr_rip_packet_t;

void sr_handle_rip_packet(struct sr_instance* sr, const uint8_t* packet, unsigned int pkt_len, unsigned int ip_off, unsigned int rip_off, unsigned int rip_len, const char* in_ifname);
void* sr_rip_send_requests(void* arg);
void sr_rip_send_response(struct sr_instance* sr, struct sr_if* interface, uint32_t ipDst);
void* sr_rip_periodic_advertisement(void* arg);
void* sr_rip_timeout_manager(void* arg);
int sr_rip_init(struct sr_instance* sr);
int sr_rip_update_route(struct sr_instance* sr, const struct sr_rip_entry_t* rte, uint32_t src_ip, const char* in_ifname);
int sr_rip_validate_packet(struct sr_rip_packet_t* packet, unsigned int len);
void sr_rip_construct_response(struct sr_instance* sr, struct sr_if* interface, struct sr_rip_packet_t* packet, int* entry_count);
void sr_rip_send_triggered_update(struct sr_instance* sr);

#endif /* SR_RIP_H */

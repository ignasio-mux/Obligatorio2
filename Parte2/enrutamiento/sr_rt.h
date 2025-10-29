/*-----------------------------------------------------------------------------
 * file:  sr_rt.h 
 * date:  Mon Oct 07 03:53:53 PDT 2002  
 * Author: casado@stanford.edu
 *
 * Description:
 *
 * Methods and datastructures for handeling the routing table
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>
#include "sr_if.h"

/* ----------------------------------------------------------------------------
 * struct sr_rt
 *
 * Node in the routing table 
 *
 * -------------------------------------------------------------------------- */

struct sr_rt
{
    struct in_addr dest;
    struct in_addr gw;
    struct in_addr mask;
    char   interface[sr_IFACE_NAMELEN];
    struct sr_rt* next;

    /* Parte 2 */
    uint8_t metric;
    uint16_t route_tag;
    uint32_t learned_from;
    time_t last_updated;
    uint8_t valid;
    time_t garbage_collection_time;
};


int sr_load_rt(struct sr_instance*,const char*);
void sr_add_rt_entry(struct sr_instance* sr,
                     struct in_addr dest,            /* destino */
                     struct in_addr gw,              /* next-hop */
                     struct in_addr mask,            /* máscara */
                     const char* if_name,            /* nombre de interfaz */
                     uint8_t metric,                 /* métrica RIP */
                     uint16_t route_tag,             /* etiqueta de ruta */
                     uint32_t learned_from,          /* IP vecino origen */
                     time_t last_updated,            /* timestamp última actualización */
                     uint8_t valid,                 /* 1 si no expiró por timeout, 0 si expiró */
                     time_t garbage_collection_time); /* tiempo para medir en garbage collection */

void sr_print_routing_table(struct sr_instance* sr);
void sr_print_routing_entry(struct sr_rt* entry);

/* Parte 2 */
void sr_del_rt_entry(struct sr_rt** head, struct sr_rt* victim);

#endif  /* --  sr_RT_H -- */

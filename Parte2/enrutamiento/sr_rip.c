/*-----------------------------------------------------------------------------
 * File:  sr_rip.c
 * Date:  Mon Sep 22 23:15:59 GMT-3 2025 
 * Authors: Santiago Freire
 * Contact: sfreire@fing.edu.uy
 *
 * Description:
 *
 * Data structures and methods for handling RIP protocol
 *
 *---------------------------------------------------------------------------*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <pthread.h>
 #include <sys/time.h>
 #include <arpa/inet.h>
 #include "sr_router.h"
 #include "sr_rt.h"
 #include "sr_rip.h"
 
 #include "sr_utils.h"
 
 static pthread_mutex_t rip_metadata_lock = PTHREAD_MUTEX_INITIALIZER;

#ifndef RIP_ENABLE_SPLIT_HORIZON
#define RIP_ENABLE_SPLIT_HORIZON 1
#endif

#ifndef RIP_ENABLE_TRIGGERED_UPDATES
#define RIP_ENABLE_TRIGGERED_UPDATES 1
#endif

#define RIP_MAX_ENTRIES_PER_PACKET 25
 
 /* Dirección MAC de multicast para los paquetes RIP */
 uint8_t rip_multicast_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x09};
 
static void sr_rip_send_updates_on_all_ifaces(struct sr_instance* sr) {
    struct sr_if* iface = sr->if_list;
    while (iface) {
        sr_rip_send_response(sr, iface, RIP_IP);
        iface = iface->next;
    }
}

static uint8_t sr_rip_normalize_metric(uint32_t metric) {
    if (metric < 1) {
        metric = 1;
    }
    if (metric > INFINITY) {
        metric = INFINITY;
    }
    return (uint8_t)metric;
}

 /* Función de validación de paquetes RIP */
 int sr_rip_validate_packet(sr_rip_packet_t* packet, unsigned int len) {
     if (len < sizeof(sr_rip_packet_t)) {
         return 0;
     }
 
     if (packet->command != RIP_COMMAND_REQUEST && packet->command != RIP_COMMAND_RESPONSE) {
         return 0;
     }
 
     if (packet->version != RIP_VERSION) {
         return 0;
     }
 
     if (packet->zero != 0) {
         return 0;
     }
 
     unsigned int expected_len = sizeof(struct sr_rip_packet_t) +
                                ((len - sizeof(struct sr_rip_packet_t)) / sizeof(struct sr_rip_entry_t)) *
                                sizeof(struct sr_rip_entry_t);
 
     if (len != expected_len) {
         return 0;
     }
 
     return 1;
 }
 
 int sr_rip_update_route(struct sr_instance* sr,
                         const struct sr_rip_entry_t* rte,
                         uint32_t src_ip,
                         const char* in_ifname)
 {
     /*
      * Procesa una entrada RIP recibida por una interfaz.
      *
 
      *  - Si la métrica anunciada es >= 16:
      *      - Si ya existe una ruta coincidente aprendida desde el mismo vecino, marca la ruta
      *        como inválida, pone métrica a INFINITY y fija el tiempo de garbage collection.
      *      - Si no, ignora el anuncio de infinito.
      *  - Calcula la nueva métrica sumando el coste del enlace de la interfaz; si resulta >=16,
      *    descarta la actualización.
      *  - Si la ruta no existe, inserta una nueva entrada en la tabla de enrutamiento.
      *  - Si la entrada existe pero está inválida, la revive actualizando métrica, gateway,
      *    learned_from, interfaz y timestamps.
      *  - Si la entrada fue aprendida del mismo vecino:
      *      - Actualiza métrica/gateway/timestamps si cambian; si no, solo refresca el timestamp.
      *  - Si la entrada viene de otro origen:
      *      - Reemplaza la ruta si la nueva métrica es mejor.
      *      - Si la métrica es igual y el next-hop coincide, refresca la entrada.
      *      - En caso contrario (peor métrica o diferente camino), ignora la actualización.
      *  - Actualiza campos relevantes: metric, gw, route_tag, learned_from, interface,
      *    last_updated, valid y garbage_collection_time según corresponda.
      *
      * Valores de retorno:
      *  - -1: entrada inválida o fallo al obtener la interfaz.
      *  -  1: la tabla de rutas fue modificada (inserción/actualización/eliminación).
      *  -  0: no se realizaron cambios.
      *
      */
 
    if (!sr || !rte || !in_ifname) {
        return -1;
    }

    struct sr_if* in_iface = sr_get_interface(sr, in_ifname);
    if (!in_iface) {
        return -1;
    }

    if (ntohs(rte->family_identifier) != 2) {
        return -1;
    }

    time_t now = time(NULL);
    uint32_t dest_ip = rte->ip;
    uint32_t mask = rte->mask;
    uint32_t network = dest_ip & mask;

    uint32_t advertised_metric = ntohl(rte->metric);
    if (advertised_metric < 1) {
        advertised_metric = 1;
    }

    struct sr_rt* existing = sr_find_learned_route(sr->routing_table, network, mask);
    uint8_t link_cost = in_iface->cost ? in_iface->cost : 1;

    if (advertised_metric >= INFINITY) {
        if (existing && existing->learned_from == src_ip) {
            if (existing->valid || existing->metric != INFINITY) {
                existing->metric = INFINITY;
                existing->valid = 0;
                existing->learned_from = src_ip;
                existing->gw.s_addr = src_ip;
                existing->garbage_collection_time = now;
                existing->last_updated = now;
                return 1;
            }
        }
        return 0;
    }

    uint32_t tentative_metric = advertised_metric + link_cost;
    if (tentative_metric >= INFINITY) {
        return 0;
    }
    uint8_t new_metric = sr_rip_normalize_metric(tentative_metric);
    uint16_t new_route_tag = ntohs(rte->route_tag);

    if (!existing) {
        struct in_addr dest_addr;
        struct in_addr mask_addr;
        struct in_addr gw_addr;

        dest_addr.s_addr = network;
        mask_addr.s_addr = mask;
        gw_addr.s_addr = src_ip;

        sr_add_rt_entry(sr,
                        dest_addr,
                        gw_addr,
                        mask_addr,
                        in_ifname,
                        new_metric,
                        new_route_tag,
                        src_ip,
                        now,
                        1,
                        0);
        return 1;
    }

    if (!existing->valid) {
        existing->metric = new_metric;
        existing->gw.s_addr = src_ip;
        existing->route_tag = new_route_tag;
        existing->learned_from = src_ip;
        strncpy(existing->interface, in_ifname, sr_IFACE_NAMELEN - 1);
        existing->interface[sr_IFACE_NAMELEN - 1] = '\0';
        existing->last_updated = now;
        existing->valid = 1;
        existing->garbage_collection_time = 0;
        return 1;
    }

    if (existing->learned_from == src_ip) {
        int changed = 0;
        if (existing->metric != new_metric) {
            existing->metric = new_metric;
            changed = 1;
        }
        if (existing->gw.s_addr != src_ip) {
            existing->gw.s_addr = src_ip;
            changed = 1;
        }
        if (existing->route_tag != new_route_tag) {
            existing->route_tag = new_route_tag;
            changed = 1;
        }
        if (strncmp(existing->interface, in_ifname, sr_IFACE_NAMELEN) != 0) {
            strncpy(existing->interface, in_ifname, sr_IFACE_NAMELEN - 1);
            existing->interface[sr_IFACE_NAMELEN - 1] = '\0';
            changed = 1;
        }
        existing->last_updated = now;
        existing->valid = 1;
        existing->garbage_collection_time = 0;
        return changed;
    }

    if (new_metric < existing->metric) {
        existing->metric = new_metric;
        existing->gw.s_addr = src_ip;
        existing->route_tag = new_route_tag;
        existing->learned_from = src_ip;
        strncpy(existing->interface, in_ifname, sr_IFACE_NAMELEN - 1);
        existing->interface[sr_IFACE_NAMELEN - 1] = '\0';
        existing->last_updated = now;
        existing->valid = 1;
        existing->garbage_collection_time = 0;
        return 1;
    }

    if (new_metric == existing->metric && existing->gw.s_addr == src_ip) {
        existing->last_updated = now;
        existing->valid = 1;
        existing->garbage_collection_time = 0;
        return 0;
    }

    return 0;
 }
 
 void sr_handle_rip_packet(struct sr_instance* sr,
                           const uint8_t* packet,
                           unsigned int pkt_len,
                           unsigned int ip_off,
                           unsigned int rip_off,
                           unsigned int rip_len,
                           const char* in_ifname)
 {
     sr_rip_packet_t* rip_packet = (struct sr_rip_packet_t*)(packet + rip_off);
 
    if (!sr || !rip_packet || !in_ifname) {
        return;
    }

    if (!sr_rip_validate_packet(rip_packet, rip_len)) {
        Debug("RIP: invalid packet received.");
        return;
    }

    pthread_mutex_lock(&rip_metadata_lock);

    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + ip_off);
    uint32_t src_ip = ip_hdr->ip_src;
    struct sr_if* in_iface = sr_get_interface(sr, in_ifname);

    if (rip_packet->command == RIP_COMMAND_REQUEST) {
        if (in_iface) {
            sr_rip_send_response(sr, in_iface, src_ip);
        }
        pthread_mutex_unlock(&rip_metadata_lock);
        return;
    }

    if (rip_packet->command != RIP_COMMAND_RESPONSE) {
        pthread_mutex_unlock(&rip_metadata_lock);
        return;
    }

    unsigned int entry_count = (rip_len - sizeof(sr_rip_packet_t)) / sizeof(sr_rip_entry_t);
    if (rip_len < sizeof(sr_rip_packet_t)) {
        pthread_mutex_unlock(&rip_metadata_lock);
        return;
    }

    int table_changed = 0;
    for (unsigned int i = 0; i < entry_count; ++i) {
        int result = sr_rip_update_route(sr, &(rip_packet->entries[i]), src_ip, in_ifname);
        if (result < 0) {
            continue;
        }
        if (result == 1) {
            table_changed = 1;
        }
    }

    if (table_changed) {
        if (RIP_ENABLE_TRIGGERED_UPDATES) {
            sr_rip_send_updates_on_all_ifaces(sr);
        }
        print_routing_table(sr);
    }

    pthread_mutex_unlock(&rip_metadata_lock);
 }
 
 void sr_rip_send_response(struct sr_instance* sr, struct sr_if* interface, uint32_t ipDst) {
     
    if (!sr || !interface) {
        return;
    }

    sr_rip_entry_t entries[RIP_MAX_ENTRIES_PER_PACKET];
    unsigned int entry_count = 0;
    struct sr_rt* route = sr->routing_table;

    while (route && entry_count < RIP_MAX_ENTRIES_PER_PACKET) {
        uint8_t metric = route->valid ? sr_rip_normalize_metric(route->metric)
                                      : INFINITY;

        if (RIP_ENABLE_SPLIT_HORIZON &&
            route->learned_from != htonl(0) &&
            strcmp(route->interface, interface->name) == 0) {
            metric = INFINITY;
        }

        entries[entry_count].family_identifier = htons(2);
        entries[entry_count].route_tag = htons(route->route_tag);
        entries[entry_count].ip = route->dest.s_addr;
        entries[entry_count].mask = route->mask.s_addr;
        entries[entry_count].next_hop = htonl(0);
        entries[entry_count].metric = htonl(metric);

        ++entry_count;
        route = route->next;
    }

    unsigned int rip_len = sizeof(sr_rip_packet_t) + entry_count * sizeof(sr_rip_entry_t);
    unsigned int udp_len = sizeof(struct sr_udp_hdr) + rip_len;
    unsigned int ip_len = sizeof(sr_ip_hdr_t) + udp_len;
    unsigned int total_len = sizeof(sr_ethernet_hdr_t) + ip_len;

    uint8_t* buf = (uint8_t*)malloc(total_len);
    if (!buf) {
        fprintf(stderr, "RIP: Failed to allocate response buffer\n");
        return;
    }
    memset(buf, 0, total_len);

    uint8_t* cursor = buf;
    sr_ethernet_hdr_t* eth = (sr_ethernet_hdr_t*)cursor;
    cursor += sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)cursor;
    cursor += sizeof(sr_ip_hdr_t);
    struct sr_udp_hdr* udp_hdr = (struct sr_udp_hdr*)cursor;
    cursor += sizeof(struct sr_udp_hdr);
    sr_rip_packet_t* rip_hdr = (sr_rip_packet_t*)cursor;

    memcpy(eth->ether_shost, interface->addr, ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_ip);

    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(ip_len);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 1;
    ip_hdr->ip_p = ip_protocol_udp;
    ip_hdr->ip_src = interface->ip;
    ip_hdr->ip_dst = ipDst;
    ip_hdr->ip_sum = 0;

    udp_hdr->src_port = htons(RIP_PORT);
    udp_hdr->dst_port = htons(RIP_PORT);
    udp_hdr->length = htons(udp_len);
    udp_hdr->checksum = 0;

    rip_hdr->command = RIP_COMMAND_RESPONSE;
    rip_hdr->version = RIP_VERSION;
    rip_hdr->zero = 0;
    memcpy(rip_hdr->entries, entries, entry_count * sizeof(sr_rip_entry_t));

    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, (uint8_t*)rip_hdr);

    int is_multicast = (ipDst == RIP_IP);
    if (is_multicast) {
        memcpy(eth->ether_dhost, rip_multicast_mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, buf, total_len, interface->name);
        free(buf);
        return;
    }

    struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), ipDst);
    if (entry) {
        memcpy(eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, buf, total_len, interface->name);
        free(entry);
        free(buf);
    } else {
        memset(eth->ether_dhost, 0, ETHER_ADDR_LEN);
        struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), ipDst, buf, total_len, interface->name);
        if (req) {
            handle_arpreq(sr, req);
        }
        free(buf);
    }
 }
 
 void* sr_rip_send_requests(void* arg) {
     sleep(3); // Esperar a que se inicialice todo
     struct sr_instance* sr = arg;
     struct sr_if* interface = sr->if_list;
     // Se envia un Request RIP por cada interfaz:
    while (interface) {
        unsigned int rip_len = sizeof(sr_rip_packet_t) + sizeof(sr_rip_entry_t);
        unsigned int udp_len = sizeof(struct sr_udp_hdr) + rip_len;
        unsigned int ip_len = sizeof(sr_ip_hdr_t) + udp_len;
        unsigned int total_len = sizeof(sr_ethernet_hdr_t) + ip_len;

        uint8_t* buf = (uint8_t*)malloc(total_len);
        if (!buf) {
            fprintf(stderr, "RIP: Failed to allocate request buffer\n");
            return NULL;
        }
        memset(buf, 0, total_len);

        uint8_t* cursor = buf;
        sr_ethernet_hdr_t* eth = (sr_ethernet_hdr_t*)cursor;
        cursor += sizeof(sr_ethernet_hdr_t);
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)cursor;
        cursor += sizeof(sr_ip_hdr_t);
        struct sr_udp_hdr* udp_hdr = (struct sr_udp_hdr*)cursor;
        cursor += sizeof(struct sr_udp_hdr);
        sr_rip_packet_t* rip_hdr = (sr_rip_packet_t*)cursor;
        sr_rip_entry_t* entry = rip_hdr->entries;

        memcpy(eth->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memcpy(eth->ether_dhost, rip_multicast_mac, ETHER_ADDR_LEN);
        eth->ether_type = htons(ethertype_ip);

        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(ip_len);
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 1;
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_src = interface->ip;
        ip_hdr->ip_dst = RIP_IP;
        ip_hdr->ip_sum = 0;

        udp_hdr->src_port = htons(RIP_PORT);
        udp_hdr->dst_port = htons(RIP_PORT);
        udp_hdr->length = htons(udp_len);
        udp_hdr->checksum = 0;

        rip_hdr->command = RIP_COMMAND_REQUEST;
        rip_hdr->version = RIP_VERSION;
        rip_hdr->zero = 0;

        entry->family_identifier = htons(0);
        entry->route_tag = 0;
        entry->ip = 0;
        entry->mask = 0;
        entry->next_hop = 0;
        entry->metric = htonl(INFINITY);

        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, (uint8_t*)rip_hdr);

        sr_send_packet(sr, buf, total_len, interface->name);
        free(buf);

        interface = interface->next;
    }

     return NULL;
 }
 
 
 /* Periodic advertisement thread */
 void* sr_rip_periodic_advertisement(void* arg) {
     struct sr_instance* sr = arg;
 
     sleep(2); // Esperar a que se inicialice todo
     
     // Agregar las rutas directamente conectadas
     /************************************************************************************/
     pthread_mutex_lock(&rip_metadata_lock);
     struct sr_if* int_temp = sr->if_list;
     while(int_temp != NULL)
     {
         struct in_addr ip;
         ip.s_addr = int_temp->ip;
         struct in_addr gw;
         gw.s_addr = 0x00000000;
         struct in_addr mask;
         mask.s_addr =  int_temp->mask;
         struct in_addr network;
         network.s_addr = ip.s_addr & mask.s_addr;
         uint8_t metric = int_temp->cost ? int_temp->cost : 1;
 
         for (struct sr_rt* it = sr->routing_table; it; it = it->next) {
         if (it->dest.s_addr == network.s_addr && it->mask.s_addr == mask.s_addr)
             sr_del_rt_entry(&sr->routing_table, it);
         }
         Debug("-> RIP: Adding the directly connected network [%s, ", inet_ntoa(network));
         Debug("%s] to the routing table\n", inet_ntoa(mask));
         sr_add_rt_entry(sr,
                         network,
                         gw,
                         mask,
                         int_temp->name,
                         metric,
                         0,
                         htonl(0),
                         time(NULL),
                         1,
                         0);
         int_temp = int_temp->next;
     }
     
     pthread_mutex_unlock(&rip_metadata_lock);
     Debug("\n-> RIP: Printing the forwarding table\n");
     print_routing_table(sr);
 
    /************************************************************************************/
    while (1) {
        sleep(RIP_ADVERT_INTERVAL_SEC);
        pthread_mutex_lock(&rip_metadata_lock);
        sr_rip_send_updates_on_all_ifaces(sr);
        pthread_mutex_unlock(&rip_metadata_lock);
    }

     return NULL;
 }
 
 /* Chequea las rutas y marca las que expiran por timeout */
 void* sr_rip_timeout_manager(void* arg) {
     struct sr_instance* sr = arg;

    while (1) {
        sleep(1);
        pthread_mutex_lock(&rip_metadata_lock);

        int changed = 0;
        time_t now = time(NULL);
        struct sr_rt* entry = sr->routing_table;

        while (entry) {
            if (entry->learned_from != htonl(0) &&
                entry->valid &&
                difftime(now, entry->last_updated) >= RIP_TIMEOUT_SEC) {
                entry->valid = 0;
                entry->metric = INFINITY;
                entry->garbage_collection_time = now;
                changed = 1;
            }
            entry = entry->next;
        }

        if (changed) {
            if (RIP_ENABLE_TRIGGERED_UPDATES) {
                sr_rip_send_updates_on_all_ifaces(sr);
            }
            print_routing_table(sr);
        }

        pthread_mutex_unlock(&rip_metadata_lock);
    }

     return NULL;
 }
 
 /* Chequea las rutas marcadas como garbage collection y las elimina si expira el timer */
 void* sr_rip_garbage_collection_manager(void* arg) {
     struct sr_instance* sr = arg;

    while (1) {
        sleep(1);
        pthread_mutex_lock(&rip_metadata_lock);

        int changed = 0;
        time_t now = time(NULL);
        struct sr_rt* entry = sr->routing_table;

        while (entry) {
            struct sr_rt* next = entry->next;
            if (entry->learned_from != htonl(0) &&
                entry->valid == 0 &&
                entry->garbage_collection_time != 0 &&
                difftime(now, entry->garbage_collection_time) >= RIP_GARBAGE_COLLECTION_SEC) {
                sr_del_rt_entry(&(sr->routing_table), entry);
                changed = 1;
            }
            entry = next;
        }

        if (changed) {
            if (RIP_ENABLE_TRIGGERED_UPDATES) {
                sr_rip_send_updates_on_all_ifaces(sr);
            }
            print_routing_table(sr);
        }

        pthread_mutex_unlock(&rip_metadata_lock);
    }

     return NULL;
 }
 
 /* Inicialización subsistema RIP */
 int sr_rip_init(struct sr_instance* sr) {
     /* Inicializar mutex */
     if(pthread_mutex_init(&sr->rip_subsys.lock, NULL) != 0) {
         printf("RIP: Error initializing mutex\n");
         return -1;
     }
 
     /* Iniciar hilo avisos periódicos */
     if(pthread_create(&sr->rip_subsys.thread, NULL, sr_rip_periodic_advertisement, sr) != 0) {
         printf("RIP: Error creating advertisement thread\n");
         pthread_mutex_destroy(&sr->rip_subsys.lock);
         return -1;
     }
 
     /* Iniciar hilo timeouts */
     pthread_t timeout_thread;
     if(pthread_create(&timeout_thread, NULL, sr_rip_timeout_manager, sr) != 0) {
         printf("RIP: Error creating timeout thread\n");
         pthread_cancel(sr->rip_subsys.thread);
         pthread_mutex_destroy(&sr->rip_subsys.lock);
         return -1;
     }
 
     /* Iniciar hilo garbage collection */
     pthread_t garbage_collection_thread;
     if(pthread_create(&garbage_collection_thread, NULL, sr_rip_garbage_collection_manager, sr) != 0) {
         printf("RIP: Error creating garbage collection thread\n");
         pthread_cancel(sr->rip_subsys.thread);
         pthread_mutex_destroy(&sr->rip_subsys.lock);
         return -1;
     }
 
     /* Iniciar hilo requests */
     pthread_t requests_thread;
     if(pthread_create(&requests_thread, NULL, sr_rip_send_requests, sr) != 0) {
         printf("RIP: Error creating requests thread\n");
         pthread_cancel(sr->rip_subsys.thread);
         pthread_mutex_destroy(&sr->rip_subsys.lock);
         return -1;
     }
 
     return 0;
 }
 
 
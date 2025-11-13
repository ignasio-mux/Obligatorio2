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
#include <stdbool.h>
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_rip.h"
#include "sr_utils.h"

static pthread_mutex_t rip_metadata_lock = PTHREAD_MUTEX_INITIALIZER;

/* Dirección MAC de multicast para los paquetes RIP */
uint8_t rip_multicast_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x09};

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

    
    /* Los campos del paquete RIP están en network byte order, convertir a host byte order */
    uint32_t costo = ntohl(rte->metric);
    uint32_t rte_ip = rte->ip;  /* Ya está en network byte order */
    uint32_t rte_mask = rte->mask;  /* Ya está en network byte order */
    time_t now = time(NULL);
    struct sr_rt* entry_in_rt = sr_find_learned_route(sr->routing_table, rte_ip, rte_mask);
    struct in_addr dest, gw, mask;

    if (costo >= 16) { 
        if (entry_in_rt != NULL && entry_in_rt->learned_from == src_ip) {
            entry_in_rt->valid = 0;
            entry_in_rt->metric = INFINITY;
            entry_in_rt->garbage_collection_time = now;
            return 1;
        } else return 0;
    }

    /* Calcula la nueva métrica sumando el coste del enlace de la interfaz */
    struct sr_if* in_enlace = sr_get_interface(sr,in_ifname);
    if (in_enlace == NULL) {
        return -1;
    }
    
    uint32_t costo_enlace = in_enlace->cost;
    uint32_t nuevo_costo = costo_enlace + costo;

    /* Si resulta >=16 descarta la actualización */
    if (nuevo_costo >= 16) {
        return 0;
    }

    /* Si la ruta no existe, inserta una nueva entrada en la tabla de enrutamiento */
    if (entry_in_rt == NULL){
        dest.s_addr = rte_ip;
        gw.s_addr = src_ip; 
        mask.s_addr = rte_mask;
        sr_add_rt_entry(sr, dest, gw, mask, in_ifname, nuevo_costo, 0, src_ip, now, 1,now);
        return 1;
    
    /* Si la entrada existe pero está inválida, la revive actualizando métrica, 
    gateway, learned_from, interfaz y timestamps */
    } else if (entry_in_rt->valid == 0) {
        entry_in_rt->metric = nuevo_costo;
        entry_in_rt->gw.s_addr = src_ip;
        entry_in_rt->learned_from = src_ip;
        memcpy(entry_in_rt->interface, in_ifname, sr_IFACE_NAMELEN);
        entry_in_rt->last_updated = now;
        entry_in_rt->valid = 1;
        return 1;
    
    /* Si la entrada fue aprendida del mismo vecino:
    Actualiza métrica/gateway/timestamps si cambian; si no, solo refresca el timestamp */
    }else {
        if (entry_in_rt->learned_from == src_ip) {
            if (entry_in_rt->metric != nuevo_costo) {
                entry_in_rt->metric = nuevo_costo;
            }
            if (entry_in_rt->gw.s_addr != src_ip) {
                entry_in_rt->gw.s_addr = src_ip;
            }
            entry_in_rt->last_updated = now;
            return 1;
    
        /* Si la entrada viene de otro origen */
        } else {
            /* - Reemplaza la ruta si la nueva métrica es mejor. */
            if(entry_in_rt->metric > nuevo_costo) {
                dest.s_addr = rte_ip;
                gw.s_addr = src_ip; 
                mask.s_addr = rte_mask;
                sr_del_rt_entry(&sr->routing_table, entry_in_rt);                
                sr_add_rt_entry(sr, dest, gw, mask, in_ifname, nuevo_costo, 0, src_ip, now, 1,now);
                return 1;
            
            /* - Si la métrica es igual y el next-hop coincide, refresca la entrada.*/
            } else if (entry_in_rt->metric == nuevo_costo && entry_in_rt->gw.s_addr == src_ip) {
                entry_in_rt->last_updated = now;                
                return 1;
            /*- En caso contrario (peor métrica o diferente camino), ignora la actualización.*/    
            }else {
                return 0;
            }
        }
    }
    return 0;
}

/* Compilar con gcc -Dtriggered_update_off para desactivar las triggered_update */
#ifndef triggered_update_off
void sr_rip_send_triggered_update(struct sr_instance* sr) {
    struct sr_if* interface = sr->if_list;
    while (interface != NULL) {
        sr_rip_send_response(sr, interface, RIP_IP);    
        interface = interface->next;
    }
}
#endif

void sr_handle_rip_packet(struct sr_instance* sr,
                          const uint8_t* packet,
                          unsigned int pkt_len,
                          unsigned int ip_off,
                          unsigned int rip_off,
                          unsigned int rip_len,
                          const char* in_ifname)
{
    
    /* Validar paquete RIP */
    
    /* Si es un RIP_COMMAND_REQUEST, enviar respuesta por la interfaz donde llegó, se sugiere usar función auxiliar 
    sr_rip_send_response */

    /* Si no es un REQUEST, entonces es un RIP_COMMAND_RESPONSE. 
    En caso que no sea un REQUEST o RESPONSE no pasa la validación. */
    
    /* Procesar entries en el paquete de RESPONSE que llegó, se sugiere usar función auxiliar sr_rip_update_route */

    /* Si hubo un cambio en la tabla, generar triggered update e imprimir tabla */

    sr_rip_packet_t* rip_packet = (sr_rip_packet_t*)(packet + rip_off);
    sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*)(packet + ip_off);
    uint32_t dest_ip = ip_packet->ip_dst;
    uint32_t orig_ip = ip_packet->ip_src;

    /* Validar paquete RIP */
    int valid = sr_rip_validate_packet(rip_packet, rip_len);
    if (valid != 1) {
        printf("Paquete RIP no válido\n");
        return ;
    }

    /* Si es un RIP_COMMAND_REQUEST, enviar respuesta por la interfaz donde llegó, 
       se sugiere usar función auxiliar sr_rip_send_response */
    if (rip_packet->command == RIP_COMMAND_REQUEST){
        struct sr_if* in_face = sr_get_interface(sr, in_ifname);
        sr_rip_send_response(sr, in_face, dest_ip);
        return;
    }
    
    /* Si no es un REQUEST, entonces es un RIP_COMMAND_RESPONSE */
    if (rip_packet->command == RIP_COMMAND_RESPONSE) {
        /* Procesar entries en el paquete de RESPONSE que llegó, se sugiere usar función auxiliar sr_rip_update_route */
        sr_rip_entry_t rip_entry;
        bool rt_changed = false;
        int num_entries = (rip_len - 4)/sizeof(sr_rip_entry_t);
        for(int i = 0; i < num_entries && i <= 25 ; i++) {
            rip_entry = rip_packet->entries[i];
            int res = sr_rip_update_route(sr, &rip_entry, orig_ip, in_ifname);
            if (res == 1)
                rt_changed = true;
        }    

        if (rt_changed){                
            /* Si hubo un cambio en la tabla, generar triggered update e imprimir tabla */
            sr_rip_send_triggered_update(sr);
            printf("La tabla de rutas es:\n");
            print_routing_table(sr);
        }
        return;
    }
            
    /* En caso que no sea un REQUEST o RESPONSE no pasa la validación. */    
    printf("Paquete RIP no valido, no es una REQUEST o RESPONSE\n");
    return;
}    

void sr_rip_send_response(struct sr_instance* sr, struct sr_if* interface, uint32_t ipDst) {
    /* Reservar buffer para paquete completo con cabecera Ethernet */
    pthread_mutex_lock(&rip_metadata_lock);
   
    /* Primero, contar cuántas entradas RIP vamos a incluir (máximo 25) */
    int entry_count = 0;
    struct sr_rt* rt = sr->routing_table;
    while (rt != NULL && entry_count < RIP_MAX_ENTRIES) {
        /* Todas las rutas se incluyen hasta el máximo (split horizon se aplica a la métrica, no a la inclusión) */
        entry_count++;
        rt = rt->next;
    }
   
    /* Calcular tamaño del paquete */
    unsigned int rip_len = sizeof(sr_rip_packet_t) + entry_count * sizeof(sr_rip_entry_t);
    unsigned int udp_len = sizeof(sr_udp_hdr_t) + rip_len;
    unsigned int ip_len = sizeof(sr_ip_hdr_t) + udp_len;
    unsigned int total_len = sizeof(sr_ethernet_hdr_t) + ip_len;
   
    uint8_t* packet = (uint8_t*)malloc(total_len);
    if (!packet) {
        pthread_mutex_unlock(&rip_metadata_lock);
        return;
    }
    memset(packet, 0, total_len);
   
    /* Construir cabecera Ethernet */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
   
    /* Determinar dirección MAC destino */
    uint8_t dst_mac[ETHER_ADDR_LEN];
   
    /* Desbloquear antes de ARP lookup para evitar posibles deadlocks */
    pthread_mutex_unlock(&rip_metadata_lock);
   
    struct sr_arpentry* arp_entry = NULL;
    if ((ntohl(ipDst) & 0xF0000000) == 0xE0000000) {
        /* Es multicast - usar MAC multicast RIP */
        memcpy(dst_mac, rip_multicast_mac, ETHER_ADDR_LEN);
    } else {
        /* Es unicast - necesitamos ARP lookup */
        arp_entry = sr_arpcache_lookup(&sr->cache, ipDst);
        if (!arp_entry) {
            /* No hay entrada ARP - liberar y retornar */
            free(packet);
            return;
        }
        memcpy(dst_mac, arp_entry->mac, ETHER_ADDR_LEN);
        free(arp_entry);
        arp_entry = NULL;
    }
   
    memcpy(eth_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);
   
    /* Construir cabecera IP */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5; /* 20 bytes / 4 = 5 */
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(ip_len);
    ip_hdr->ip_id = htons(0); /* Puede ser cualquier valor */
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 1; /* RIP usa TTL=1 */
    ip_hdr->ip_p = ip_protocol_udp;
    ip_hdr->ip_sum = 0; /* Se calculará después */
    ip_hdr->ip_src = interface->ip;
    ip_hdr->ip_dst = ipDst;
   
    /* Construir cabecera UDP */
    sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    udp_hdr->src_port = htons(RIP_PORT);
    udp_hdr->dst_port = htons(RIP_PORT);
    udp_hdr->length = htons(udp_len);
    udp_hdr->checksum = 0; /* Se calculará después */
   
    /* Construir paquete RIP con las entradas de la tabla */
    sr_rip_packet_t* rip_packet = (sr_rip_packet_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
   
    /* Armar encabezado RIP de la respuesta */
    rip_packet->command = RIP_COMMAND_RESPONSE;
    rip_packet->version = RIP_VERSION;
    rip_packet->zero = 0;
   
    /* Recorrer toda la tabla de enrutamiento hasta el máximo de 25 rutas - bloquear de nuevo para acceder a la tabla */
    pthread_mutex_lock(&rip_metadata_lock);
    int entry_idx = 0;
    rt = sr->routing_table;
    while (rt != NULL && entry_idx < RIP_MAX_ENTRIES) {
        sr_rip_entry_t* entry = &rip_packet->entries[entry_idx];
       
        /* Considerar split horizon con poisoned reverse y rutas expiradas por timeout cuando corresponda */
        uint32_t metric = rt->metric;
        
        /* Si la ruta es inválida (expiró por timeout), usar métrica INFINITY */
        if (rt->valid == 0) {
            metric = INFINITY;
        } else if (rt->learned_from != 0) {
            /* Ruta aprendida de un vecino - verificar split horizon con poisoned reverse */
            #if ENABLE_SPLIT_HORIZON_POISONED_REVERSE
            struct sr_if* learned_if = sr_get_interface(sr, rt->interface);
            if (learned_if && strcmp(learned_if->name, interface->name) == 0) {
                /* Split horizon con poisoned reverse: anunciar con métrica INFINITY */
                metric = INFINITY;
            }
            #endif
        }
       
        /* Normalizar métrica a rango RIP (1..INFINITY) */
        if (metric == 0) {
            metric = 1;
        } else if (metric > INFINITY) {
            metric = INFINITY;
        }
       
        /* Armar la entrada RIP */
        entry->family_identifier = htons(2); /* IPv4 */
        entry->route_tag = htons(rt->route_tag);
        entry->ip = rt->dest.s_addr; /* Ya está en network byte order */
        entry->mask = rt->mask.s_addr; /* Ya está en network byte order */
        entry->next_hop = htonl(0); /* Siempre 0.0.0.0 */
        entry->metric = htonl(metric);
       
        entry_idx++;
        rt = rt->next;
    }
   
    pthread_mutex_unlock(&rip_metadata_lock);
   
    /* Calcular longitudes del paquete */
    /* Ya calculadas arriba */
   
    /* Calcular checksums */
    /* Checksum IP */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
   
    /* Checksum UDP */
    uint8_t* udp_payload = (uint8_t*)rip_packet;
    udp_hdr->checksum = 0;
    udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, udp_payload);
   
    /* Enviar paquete */
    sr_send_packet(sr, packet, total_len, interface->name);
    free(packet);
}

void* sr_rip_send_requests(void* arg) {
    sleep(3); // Esperar a que se inicialice todo
    struct sr_instance* sr = arg;
    struct sr_if* interface = sr->if_list;
    
    // Se envia un Request RIP por cada interfaz:
    while (interface != NULL) {
        /* Calcular longitudes del paquete */
        unsigned int rip_entry_size = sizeof(sr_rip_entry_t);
        unsigned int rip_packet_size = sizeof(sr_rip_packet_t) + rip_entry_size;
        unsigned int udp_len = sizeof(sr_udp_hdr_t) + rip_packet_size;
        unsigned int ip_len = sizeof(sr_ip_hdr_t) + udp_len;
        unsigned int total_len = sizeof(sr_ethernet_hdr_t) + ip_len;
        
        /* Reservar buffer para paquete completo con cabecera Ethernet */
        uint8_t* packet = (uint8_t*)malloc(total_len);
        if (!packet) {
            printf("RIP: Error allocating memory for request packet\n");
            interface = interface->next;
            continue;
        }
        memset(packet, 0, total_len);
        
        /* Construir cabecera Ethernet */
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
        memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, rip_multicast_mac, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_ip);
        
        /* Construir cabecera IP */
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5; /* 5 palabras de 32 bits = 20 bytes */
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(ip_len);
        ip_hdr->ip_id = htons(0);
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 1; /* RIP usa TTL=1 */
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_sum = 0; /* Se calculará después */
        ip_hdr->ip_src = interface->ip;
        ip_hdr->ip_dst = htonl(RIP_IP); /* 224.0.0.9 */
        
        /* Construir cabecera UDP */
        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->src_port = htons(RIP_PORT);
        udp_hdr->dst_port = htons(RIP_PORT);
        udp_hdr->length = htons(udp_len);
        udp_hdr->checksum = 0; /* Se calculará después */
        
        /* Construir paquete RIP */
        sr_rip_packet_t* rip_packet = (sr_rip_packet_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_packet->command = RIP_COMMAND_REQUEST;
        rip_packet->version = RIP_VERSION;
        rip_packet->zero = 0;
        
        /* Entrada para solicitar la tabla de ruteo completa (ver RFC 2453) */
        /* Una entrada con family_identifier=0 indica solicitud de toda la tabla */
        sr_rip_entry_t* rip_entry = (sr_rip_entry_t*)(rip_packet->entries);
        rip_entry->family_identifier = 0; /* Solicita toda la tabla */
        rip_entry->route_tag = 0;
        rip_entry->ip = 0;
        rip_entry->mask = 0;
        rip_entry->next_hop = 0;
        rip_entry->metric = htonl(INFINITY); /* Debe ser 16 (INFINITY) según RFC */
        
        /* Calcular checksums */
        ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, (uint8_t*)rip_packet);
        
        /* Enviar paquete */
        Debug("RIP: Sending request packet on interface %s\n", interface->name);
        sr_send_packet(sr, packet, total_len, interface->name);
        free(packet);
        
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

    /* 
        Espera inicial de RIP_ADVERT_INTERVAL_SEC antes del primer envío.
        A continuación entra en un bucle infinito que, cada RIP_ADVERT_INTERVAL_SEC segundos,
        recorre la lista de interfaces (sr->if_list) y envía una respuesta RIP por cada una,
        utilizando la dirección de multicast definida (RIP_IP).
        Esto implementa el envío periódico de rutas (anuncios no solicitados) en RIPv2.
    */
    
    /* Espera inicial de RIP_ADVERT_INTERVAL_SEC antes del primer envío */
    sleep(RIP_ADVERT_INTERVAL_SEC);
    
    /* Bucle infinito para envíos periódicos */
    while (1) {
        /* Recorrer todas las interfaces activas */
        struct sr_if* interface = sr->if_list;
        while (interface != NULL) {
            /* Enviar respuesta RIP por multicast (RIP_IP) a través de esta interfaz */
            sr_rip_send_response(sr, interface, htonl(RIP_IP));
            interface = interface->next;
        }
        
        /* Esperar RIP_ADVERT_INTERVAL_SEC segundos antes del siguiente envío */
        sleep(RIP_ADVERT_INTERVAL_SEC);
    }
    
    return NULL;
}

/* Chequea las rutas y marca las que expiran por timeout */
void* sr_rip_timeout_manager(void* arg) {
    struct sr_instance* sr = arg;
    
    /* Bucle periódico que espera 1 segundo entre comprobaciones */
    while (1) {
        sleep(1);
        
        time_t current_time = time(NULL);
        int changes_detected = 0;
        
        /* Proteger el acceso concurrente a la tabla de enrutamiento */
        pthread_mutex_lock(&rip_metadata_lock);
        
        /* Recorre la tabla de enrutamiento */
        struct sr_rt* rt = sr->routing_table;
        while (rt != NULL) {
            /* Verificar si es una ruta dinámica (aprendida de un vecino) */
            /* learned_from != 0 indica que fue aprendida de un vecino */
            if (rt->learned_from != 0 && rt->valid == 1) {
                /* Calcular el tiempo transcurrido desde la última actualización */
                double time_elapsed = difftime(current_time, rt->last_updated);
                
                /* Si no se ha actualizado en el intervalo de timeout */
                if (time_elapsed >= RIP_TIMEOUT_SEC) {
                    Debug("RIP: Route timeout detected for ");
                    Debug("%s/%s\n", inet_ntoa(rt->dest), inet_ntoa(rt->mask));
                    
                    /* Marcar la ruta como inválida */
                    rt->valid = 0;
                    
                    /* Fijar su métrica a INFINITY */
                    rt->metric = INFINITY;
                    
                    /* Anotar el tiempo de inicio del proceso de garbage collection */
                    rt->garbage_collection_time = current_time;
                    
                    changes_detected = 1;
                }
            }
            
            rt = rt->next;
        }
        
        pthread_mutex_unlock(&rip_metadata_lock);
        
        /* Si se detectaron cambios, desencadenar una actualización (triggered update) */
        if (changes_detected) {
            Debug("RIP: Timeout changes detected, sending triggered update\n");
            sr_rip_send_triggered_update(sr);
            
            /* Actualizar/visualizar la tabla de enrutamiento */
            pthread_mutex_lock(&rip_metadata_lock);
            Debug("\n-> RIP: Printing the forwarding table after timeout\n");
            print_routing_table(sr);
            pthread_mutex_unlock(&rip_metadata_lock);
        }
    }
    
    return NULL;
}

/* Chequea las rutas marcadas como garbage collection y las elimina si expira el timer */
void* sr_rip_garbage_collection_manager(void* arg) {
    struct sr_instance* sr = arg;
    /*
        - Bucle infinito que espera 1 segundo entre comprobaciones.
        - Recorre la tabla de enrutamiento y elimina aquellas rutas que:
            * estén marcadas como inválidas (valid == 0) y
            * lleven más tiempo en garbage collection que RIP_GARBAGE_COLLECTION_SEC
              (current_time >= garbage_collection_time + RIP_GARBAGE_COLLECTION_SEC).
        - Si se detectan eliminaciones, se imprime la tabla.
        - Se debe usar el mutex rip_metadata_lock para proteger el acceso concurrente
          a la tabla de enrutamiento.
    */
   
    // Bucle infinito que espera 1 segundo entre comprobaciones
    while (1) {
        sleep(1);  // Esperar 1 segundo entre comprobaciones
       
        pthread_mutex_lock(&rip_metadata_lock);
       
        time_t current_time = time(NULL);
        int deletions_occurred = 0;
       
        // Recorrer la tabla de enrutamiento y eliminar rutas que cumplan las condiciones
        // Usar un enfoque seguro: guardar el siguiente antes de eliminar
        struct sr_rt* rt = sr->routing_table;
        struct sr_rt* next;
       
        while (rt != NULL) {
            // Guardar el siguiente nodo antes de cualquier eliminación
            next = rt->next;
           
            // Verificar condiciones para eliminar:
            // 1. La ruta debe estar marcada como inválida (valid == 0)
            // 2. Debe haber pasado más tiempo que RIP_GARBAGE_COLLECTION_SEC desde garbage_collection_time
            if (rt->valid == 0 &&
                rt->garbage_collection_time != 0 &&
                current_time >= rt->garbage_collection_time + RIP_GARBAGE_COLLECTION_SEC) {
               
                // Eliminar la ruta de la tabla
                sr_del_rt_entry(&sr->routing_table, rt);
                deletions_occurred = 1;
            }
           
            // Continuar con el siguiente nodo (ya guardado antes de la posible eliminación)
            rt = next;
        }
       
        // Si se detectaron eliminaciones, imprimir la tabla
        if (deletions_occurred) {
            Debug("\n-> RIP: Garbage collection: Routes removed, printing routing table\n");
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


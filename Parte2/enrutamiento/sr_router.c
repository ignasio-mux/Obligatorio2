/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_rip.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

/* Verifica si una IP pertenece a alguna de nuestras interfaces */
int is_packet_for_me(struct sr_instance *sr, uint32_t ip) {
    struct sr_if *iface = sr->if_list;
    
    while (iface) {
        if (iface->ip == ip) {
            return 1;
        }
        iface = iface->next;
    }
    
    return 0;
}

/* Declaración forward */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface);

/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

  /* COLOQUE AQUÍ SU CÓDIGO*/

  /* Tamaños base */

    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) ipPacket;
    unsigned int len_ipPacket = ntohs(ipHeader->ip_len);

    if (type == 3 || type == 11) {
        unsigned int len_icmp = sizeof(sr_icmp_t3_hdr_t);
        unsigned int len_ip   = sizeof(sr_ip_hdr_t);
        unsigned int len_eth  = sizeof(sr_ethernet_hdr_t);
        unsigned int total_len = len_eth + len_ip + len_icmp;

        /* Reserva de memoria */
        uint8_t *ethernet_trama = malloc(total_len);
        if (!ethernet_trama) return;


        /* ICMP */
        sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(ethernet_trama + len_eth + len_ip);
        /* memset(icmp_hdr, 0, len_icmp); */
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 0;

        /* Copiar cabecera IP + primeros 8 bytes del paquete original */    
        unsigned int imcp_data_len = (len_ipPacket < 28) ? len_ipPacket : 28;
        memcpy(icmp_hdr->data, ipPacket, imcp_data_len);    

        /* Checksum ICMP */
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = icmp3_cksum(icmp_hdr, len_icmp);

        /* IP */
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ethernet_trama + len_eth);
        /* memset(ip_hdr, 0, len_ip); */ 
        ip_hdr->ip_v = 4;
        /* ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4; */
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_off = htons(IP_DF);
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(len_ip + len_icmp);
        ip_hdr->ip_ttl = 64;
        /* ip_protocol_icmp = 0x0001 */
        ip_hdr->ip_p = 1;
        ip_hdr->ip_dst = ipDst;

        /* Buscar interfaz de salida */
        struct sr_rt *match = sr_find_lpm_entry(sr, ipDst);
        if (!match) {
            /* sr_send_icmp_error_packet(3,0,sr,ip,ip_paquete); */
            free(ethernet_trama);
            return;
        }
        struct sr_if *iface = sr_get_interface(sr, match->interface);
        ip_hdr->ip_src = iface->ip;

        /* Checksum IP */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = ip_cksum(ip_hdr, len_ip);

        /* Ethernet */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)ethernet_trama;
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        /* Tipo de protocolo encapsulado en el paquete Ethernet. 
        Para IPv4 es 0x0800 pero debe enviarse 0x0008 Big-endian  */
        eth_hdr->ether_type = htons(ethertype_ip);

        /* Resolver siguiente salto */
        uint32_t next_hop_ip = (match->gw.s_addr) ? match->gw.s_addr : ipDst;
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
        if (arp_entry) {
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, ethernet_trama, total_len, iface->name);
            free(arp_entry);
            free(ethernet_trama);
        } else {
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, ethernet_trama, total_len, iface->name);
            handle_arpreq(sr, req);
        }
    } else if (type == 0){
        unsigned int len_icmp = sizeof(sr_icmp_hdr_t);
        unsigned int len_ip   = sizeof(sr_ip_hdr_t);
        unsigned int len_eth  = sizeof(sr_ethernet_hdr_t);
        unsigned int headers_len = len_eth + len_ip + len_icmp;
        unsigned int total_len = len_eth + len_ip + len_icmp + 60;

        /* Reserva de memoria */
        uint8_t *ethernet_trama = malloc(total_len);
        if (!ethernet_trama) return;
        /* Crear buffer para el reply */

        memcpy(ethernet_trama+headers_len, ipPacket+headers_len-len_eth, 60);
    
        /* ICMP */
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ethernet_trama + len_eth + len_ip);
        /* memset(icmp_hdr, 0, len_icmp); */
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;

        /* Checksum ICMP */
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, 64);

        /* IP */
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ethernet_trama + len_eth);
        /* memset(ip_hdr, 0, len_ip); */ 
        ip_hdr->ip_v = 4;
        /* ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4; */
        ip_hdr->ip_off = htons(IP_DF);
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_id = htons(0);
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(len_ip + 64);
        ip_hdr->ip_ttl = 64;
        /* ip_protocol_icmp = 0x0001 */
        ip_hdr->ip_p = 1;
        ip_hdr->ip_dst = ipDst;

        /* Buscar interfaz de salida */
        struct sr_rt *match = sr_find_lpm_entry(sr, ipDst);
        struct sr_if *iface = NULL;
        
        if (!match) {
            /* No se encontró ruta en la tabla, buscar en interfaces directamente conectadas */
            struct sr_if *if_walker = sr->if_list;
            while (if_walker) {
                /* Verificar si la IP destino está en la red de esta interfaz */
                uint32_t network = if_walker->ip & if_walker->mask;
                uint32_t dst_network = ipDst & if_walker->mask;
                if (network == dst_network) {
                    iface = if_walker;
                    break;
                }
                if_walker = if_walker->next;
            }
            if (!iface) {
                free(ethernet_trama);
                return;
            }
        } else {
            iface = sr_get_interface(sr, match->interface);
            if (!iface) {
                free(ethernet_trama);
                return;
            }
        }
        ip_hdr->ip_src = iface->ip;

        /* Checksum IP */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = ip_cksum(ip_hdr, len_ip);

        /* Ethernet */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)ethernet_trama;
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        /* Tipo de protocolo encapsulado en el paquete Ethernet. 
        Para IPv4 es 0x0800 pero debe enviarse 0x0008 Big-endian  */
        eth_hdr->ether_type = htons(ethertype_ip);
        
        /* Resolver siguiente salto */
        uint32_t next_hop_ip;
        if (match) {
            next_hop_ip = (match->gw.s_addr) ? match->gw.s_addr : ipDst;
        } else {
            /* Si no hay ruta en la tabla, es una red directamente conectada, usar IP destino */
            next_hop_ip = ipDst;
        }
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
        if (arp_entry) {
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, ethernet_trama, total_len, iface->name);
            free(arp_entry);
            free(ethernet_trama);
        } else {
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, ethernet_trama, total_len, iface->name);
            handle_arpreq(sr, req);
        }

    }
} /* -- sr_send_icmp_error_packet -- */

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /*
  * COLOQUE ASÍ SU CÓDIGO
  * SUGERENCIAS:
  * - Obtener el cabezal IP y direcciones
  * - Verificar si el paquete es para una de mis interfaces o si hay una coincidencia en mi tabla de enrutamiento
  * - Si no es para una de mis interfaces y no hay coincidencia en la tabla de enrutamiento, enviar ICMP net unreachable
  * - Si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply
  * - Si es para mí o a la IP multicast de RIP, verificar si contiene un datagrama UDP y es destinado al puerto RIP, en ese caso pasarlo al subsistema RIP.
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

  printf("*** -> Processing IP packet\n");
    
    /* Obtener el cabezal IP */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t dest_ip = ip_hdr->ip_dst;
    uint32_t src_ip = ip_hdr->ip_src;
    
    printf("*** -> IP packet: ");
    print_addr_ip_int(htonl(src_ip));
    printf(" -> ");
    print_addr_ip_int(htonl(dest_ip));
    printf("\n");
    
    /* Actualizar caché ARP con la MAC origen del paquete */
    /* Esto permite aprender la MAC del remitente cuando recibimos un paquete IP */
    struct sr_arpentry *existing_entry = sr_arpcache_lookup(&sr->cache, src_ip);
    if (!existing_entry) {
        /* No existe entrada ARP, insertar la nueva asociación IP->MAC */
        sr_arpcache_insert(&sr->cache, srcAddr, src_ip);
    } else {
        /* Ya existe entrada, verificar si la MAC cambió */
        if (memcmp(existing_entry->mac, srcAddr, ETHER_ADDR_LEN) != 0) {
            /* MAC cambió, actualizar la entrada */
            sr_arpcache_insert(&sr->cache, srcAddr, src_ip);
        }
        free(existing_entry);
    }
    
    /* Verificar si el paquete es para una de nuestras interfaces */
    if (is_packet_for_me(sr, dest_ip)) {
        printf("*** -> Packet is for us\n");
        
        /* Verificar si es un ICMP echo request */
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            
            if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) { /* Echo request */
                printf("*** -> ICMP echo request received, sending echo reply\n");
                uint8_t *ipPacket = (packet + sizeof(sr_ethernet_hdr_t));
                sr_send_icmp_error_packet(0,0,sr,src_ip,ipPacket);
                return;
            }

        } else if (ip_hdr->ip_p == ip_protocol_udp) {
            sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));    
            
            if  (ntohs(udp_hdr->dst_port) == RIP_PORT) {
                unsigned int ip_off = sizeof(sr_ethernet_hdr_t);
                unsigned int rip_off = ip_off + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) ;
                unsigned int rip_len = len - rip_off;
                sr_handle_rip_packet(sr, packet, len, ip_off, rip_off, rip_len, interface);
            } else {
                printf("$$$ -> Received UDP/TCP for router, sending ICMP Port Unreachable\n");
                uint8_t *ipPacket = (packet + sizeof(sr_ethernet_hdr_t));
                sr_send_icmp_error_packet(3,3,sr,src_ip,ipPacket);            
            }
       
        } else if (ip_hdr->ip_p == 0x0006) {
            printf("$$$ -> Received UDP/TCP for router, sending ICMP Port Unreachable\n");
            uint8_t *ipPacket = (packet + sizeof(sr_ethernet_hdr_t));
            sr_send_icmp_error_packet(3,3,sr,src_ip,ipPacket);            
        }

    } else if (dest_ip == htonl(RIP_IP) && ip_hdr->ip_p == ip_protocol_udp) {
        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (ntohs(udp_hdr->dst_port) == RIP_PORT) {
            unsigned int ip_off = sizeof(sr_ethernet_hdr_t);
            unsigned int rip_off = ip_off + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) ;
            unsigned int rip_len = len - rip_off;
            sr_handle_rip_packet(sr, packet, len, ip_off, rip_off, rip_len, interface);
        }    
    }    

    /* Buscar en la tabla de enrutamiento */
    struct sr_rt *route = sr_find_lpm_entry(sr, dest_ip);
    if (!route) {
        printf("*** -> No route found, sending ICMP net unreachable\n");
        sr_send_icmp_error_packet(3, 0, sr, src_ip, packet + sizeof(sr_ethernet_hdr_t));
        return;
    }
    
    printf("*** -> Route found: ");
    print_addr_ip_int(htonl(route->dest.s_addr));
    printf(" via ");
    print_addr_ip_int(htonl(route->gw.s_addr));
    printf(" on interface %s\n", route->interface);
    
    /* Verificar TTL */
    if (ip_hdr->ip_ttl <= 1) {
        printf("*** -> TTL expired, sending ICMP time exceeded\n");
        sr_send_icmp_error_packet(11, 0, sr, src_ip, packet + sizeof(sr_ethernet_hdr_t));
        return;
    }
    
    /* Decrementar TTL */
    ip_hdr->ip_ttl--;
    
    /* Recalcular checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    
    /* Determinar la IP del siguiente salto */
    uint32_t next_hop_ip = (route->gw.s_addr == 0) ? dest_ip : route->gw.s_addr;
    
    /* Buscar en la caché ARP */
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    
    if (entry) {
        printf("*** -> ARP entry found, forwarding packet\n");
        
        /* Actualizar cabezal Ethernet */
        memcpy(eHdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        
        /* Obtener la interfaz de salida */
        struct sr_if *out_iface = sr_get_interface(sr, route->interface);
        if (out_iface) {
            memcpy(eHdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, route->interface);
        }
        
        free(entry);
    } else {
        printf("*** -> No ARP entry found, queuing packet for ARP request\n");
        
        /* Crear una copia del paquete para la cola ARP */
        uint8_t *packet_copy = malloc(len);
        memcpy(packet_copy, packet, len);
        
        /* Agregar a la cola ARP */
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet_copy, len, route->interface);
        
        /* Enviar solicitud ARP */
        handle_arpreq(sr, req);
    }


}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* COLOQUE SU CÓDIGO AQUÍ

  SUGERENCIAS:
  - Verifique si se trata de un ARP request o ARP reply
  - Si es una ARP request, antes de responder verifique si el mensaje consulta por la dirección MAC asociada a una dirección IP configurada en una interfaz del router
  - Si es una ARP reply, agregue el mapeo MAC->IP del emisor a la caché ARP y envíe los paquetes que hayan estado esperando por el ARP reply
  */

  /* Verificar que la longitud del paquete sea suficiente para los encabezados Ethernet + ARP */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        printf("*** -> Paquete ARP demasiado corto, descartando.\n");
        return;
    }

    /* Obtener el encabezado ARP */
    sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Verificar el formato del paquete ARP (tipo de hardware, protocolo, etc.) */
    if (ntohs(arpHdr->ar_hrd) != 1 || /* Ethernet */
        ntohs(arpHdr->ar_pro) != ethertype_ip || /* IP */
        arpHdr->ar_hln != ETHER_ADDR_LEN || /* Longitud de MAC */
        arpHdr->ar_pln != 4) { /* Longitud de IP */
        printf("*** -> Formato de paquete ARP inválido, descartando.\n");
        return;
    }

    /* Determinar si es una solicitud o respuesta ARP */
    uint16_t arp_op = ntohs(arpHdr->ar_op);

    if (arp_op == arp_op_request) {
        /* Manejar solicitud ARP */
        printf("*** -> Solicitud ARP recibida.\n");

        /* Verificar si la solicitud es para una de nuestras interfaces */
        struct sr_if *iface = sr_get_interface_given_ip(sr, arpHdr->ar_tip);
        if (iface) {
            /* La solicitud es para nuestra dirección MAC, enviar una respuesta ARP */
            printf("*** -> Solicitud ARP para nuestra IP %s, enviando respuesta.\n", inet_ntoa(*(struct in_addr *)&arpHdr->ar_tip));

            /* Asignar memoria para el paquete de respuesta ARP */
            int arpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *arpReply = (uint8_t *)malloc(arpPacketLen);
            if (!arpReply) {
                printf("*** -> Falló la asignación de memoria para la respuesta ARP.\n");
                return;
            }

            /* Construir el encabezado Ethernet */
            sr_ethernet_hdr_t *replyEthHdr = (sr_ethernet_hdr_t *)arpReply;
            memcpy(replyEthHdr->ether_dhost, arpHdr->ar_sha, ETHER_ADDR_LEN); /* MAC del emisor */
            memcpy(replyEthHdr->ether_shost, iface->addr, ETHER_ADDR_LEN); /* Nuestra MAC de interfaz */
            replyEthHdr->ether_type = htons(ethertype_arp);

            /* Construir el encabezado ARP */
            sr_arp_hdr_t *replyArpHdr = (sr_arp_hdr_t *)(arpReply + sizeof(sr_ethernet_hdr_t));
            replyArpHdr->ar_hrd = htons(1); /* Ethernet */
            replyArpHdr->ar_pro = htons(ethertype_ip); /* IP */
            replyArpHdr->ar_hln = ETHER_ADDR_LEN; /* Longitud de MAC */
            replyArpHdr->ar_pln = 4; /* Longitud de IP */
            replyArpHdr->ar_op = htons(arp_op_reply); /* Respuesta ARP */
            memcpy(replyArpHdr->ar_sha, iface->addr, ETHER_ADDR_LEN); /* Nuestra MAC */
            memcpy(replyArpHdr->ar_tha, arpHdr->ar_sha, ETHER_ADDR_LEN); /* MAC del emisor */
            replyArpHdr->ar_sip = iface->ip; /* Nuestra IP */
            replyArpHdr->ar_tip = arpHdr->ar_sip; /* IP del emisor */

            /* Enviar la respuesta ARP */
            print_hdr_arp((uint8_t *)replyArpHdr);
            sr_send_packet(sr, arpReply, arpPacketLen, iface->name);
            free(arpReply);
        } else {
            printf("*** -> Solicitud ARP no es para nuestra IP, ignorando.\n");
        }
    } else if (arp_op == arp_op_reply) {
         /* Manejar respuesta ARP */
        printf("*** -> Respuesta ARP recibida.\n");

        /* Insertar el mapeo IP->MAC en la caché ARP */
        struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arpHdr->ar_sha, arpHdr->ar_sip);
        if (req) {
            /* Obtener la interfaz por la que llegó el paquete */
            struct sr_if *iface = sr_get_interface(sr, interface);
            if (iface) {
                /* Enviar todos los paquetes pendientes usando la función auxiliar */
                sr_arp_reply_send_pending_packets(sr, req, arpHdr->ar_sha, iface->addr, iface);
            }
            
            /* Destruir la solicitud ARP ya que se recibió la respuesta */
            sr_arpreq_destroy(&sr->cache, req);
        }
    } else {
        printf("*** -> Operación ARP desconocida %d, descartando.\n", arp_op);
    }
}

/*
* ***** A partir de aquí no debería tener que modificar nada ****
*/

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     print_hdrs(copyPacket, currPacket->len);
     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
     free(copyPacket);
     currPacket = currPacket->next;
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */
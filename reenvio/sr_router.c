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

/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

  /* COLOQUE AQUÍ SU CÓDIGO*/

} /* -- sr_send_icmp_error_packet -- */

/* Busca la mejor ruta para una IP usando Longest Prefix Match */
struct sr_rt* sr_lpm_lookup(struct sr_instance *sr, uint32_t ip) {
    struct sr_rt *rt = sr->routing_table;
    struct sr_rt *best_match = NULL;
    uint32_t best_mask = 0;
    
    while (rt) {
        if ((rt->dest.s_addr & rt->mask.s_addr) == (ip & rt->mask.s_addr)) {
            uint32_t mask_val = ntohl(rt->mask.s_addr);
            if (mask_val > best_mask) {
                best_mask = mask_val;
                best_match = rt;
            }
        }
        rt = rt->next;
    }
    
    return best_match;
}

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

/* Envía una respuesta ICMP echo reply */
void sr_send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    printf("*** -> Sending ICMP echo reply\n");
    
    /* Obtener cabezales */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* Crear una copia del paquete */
    uint8_t *reply_packet = malloc(len);
    memcpy(reply_packet, packet, len);
    
    /* Actualizar cabezal Ethernet */
    sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply_packet;
    memcpy(reply_eth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    
    /* Actualizar cabezal IP */
    sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_ip->ip_src = ip_hdr->ip_dst;
    reply_ip->ip_dst = ip_hdr->ip_src;
    reply_ip->ip_sum = 0; /* Se recalculará */
    
    /* Actualizar cabezal ICMP */
    sr_icmp_hdr_t *reply_icmp = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    reply_icmp->icmp_type = 0; /* Echo reply */
    reply_icmp->icmp_code = 0;
    reply_icmp->icmp_sum = 0; /* Se recalculará */
    
    /* Recalcular checksums */
    reply_ip->ip_sum = ip_cksum(reply_ip, sizeof(sr_ip_hdr_t));
    reply_icmp->icmp_sum = icmp_cksum(reply_icmp, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    
    /* Enviar el paquete */
    sr_send_packet(sr, reply_packet, len, interface);
    free(reply_packet);
    
    printf("*** -> ICMP echo reply sent\n");
}

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

    printf("*** -> Processing IP packet\n");
    
    /* Obtener el cabezal IP */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t dest_ip = ip_hdr->ip_dst;
    uint32_t src_ip = ip_hdr->ip_src;
    
    printf("*** -> IP packet: ");
    print_addr_ip_int(src_ip);
    printf(" -> ");
    print_addr_ip_int(dest_ip);
    printf("\n");
    
    /* Verificar si el paquete es para una de nuestras interfaces */
    if (is_packet_for_me(sr, dest_ip)) {
        printf("*** -> Packet is for us\n");
        
        /* Verificar si es un ICMP echo request */
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            
            if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) { /* Echo request */
                printf("*** -> ICMP echo request received, sending echo reply\n");
                sr_send_icmp_echo_reply(sr, packet, len, interface);
                return;
            }
        }
        
        printf("*** -> Not an ICMP echo request, dropping packet\n");
        return;
    }
    
    /* Buscar en la tabla de enrutamiento */
    struct sr_rt *route = sr_lpm_lookup(sr, dest_ip);
    if (!route) {
        printf("*** -> No route found, sending ICMP net unreachable\n");
        sr_send_icmp_error_packet(3, 0, sr, src_ip, packet + sizeof(sr_ethernet_hdr_t));
        return;
    }
    
    printf("*** -> Route found: ");
    print_addr_ip_int(route->dest.s_addr);
    printf(" via ");
    print_addr_ip_int(route->gw.s_addr);
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
    
    printf("*** -> Next hop IP: ");
    print_addr_ip_int(next_hop_ip);
    printf("\n");
    
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
        sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet_copy, len, route->interface);
        
        /* Enviar solicitud ARP */
        sr_arp_request_send(sr, next_hop_ip);
    }
}

/* Envía una respuesta ARP */
void sr_arp_reply_send(struct sr_instance *sr, uint32_t target_ip, uint8_t *target_mac, struct sr_if *iface) {
    printf("* -> Sending ARP reply to IP: ");
    print_addr_ip_int(target_ip);
    printf("\n");
    
    /* Construir el paquete ARP reply */
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed for ARP reply packet\n");
        return;
    }
    
    /* Cabezal Ethernet */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
    memcpy(ehdr->ether_dhost, target_mac, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    ehdr->ether_type = htons(ethertype_arp);
    
    /* Cabezal ARP */
    sr_arp_hdr_t *ahdr = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    ahdr->ar_hrd = htons(arp_hrd_ethernet);
    ahdr->ar_pro = htons(ethertype_ip);
    ahdr->ar_hln = ETHER_ADDR_LEN;
    ahdr->ar_pln = 4;  /* Longitud de dirección IP */
    ahdr->ar_op = htons(arp_op_reply);
    memcpy(ahdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    ahdr->ar_sip = iface->ip;
    memcpy(ahdr->ar_tha, target_mac, ETHER_ADDR_LEN);
    ahdr->ar_tip = target_ip;
    
    /* Enviar el paquete */
    sr_send_packet(sr, buf, len, iface->name);
    free(buf);
    
    printf("* -> ARP reply sent successfully\n");
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
     currPacket = currPacket->next;
  }
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *packet /* prestado */,
                          unsigned int len,
                          uint8_t *srcAddr,
                          uint8_t *destAddr,
                          char *interface /* prestado */,
                          sr_ethernet_hdr_t *eHdr)
{
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
            /* Enviar todos los paquetes pendientes que esperaban esta respuesta ARP */
            struct sr_packet *currPacket = req->packets;
            while (currPacket) {
                sr_ethernet_hdr_t *pktEthHdr = (sr_ethernet_hdr_t *)currPacket->buf;
                memcpy(pktEthHdr->ether_shost, sr_get_interface(sr, currPacket->iface)->addr, ETHER_ADDR_LEN);
                memcpy(pktEthHdr->ether_dhost, arpHdr->ar_sha, ETHER_ADDR_LEN);

                /* Crear una copia del paquete para enviar */
                uint8_t *copyPacket = (uint8_t *)malloc(currPacket->len);
                if (!copyPacket) {
                    printf("*** -> Falló la asignación de memoria para la copia del paquete.\n");
                    currPacket = currPacket->next;
                    continue;
                }
                memcpy(copyPacket, currPacket->buf, currPacket->len);

                /* Enviar el paquete */
                print_hdrs(copyPacket, currPacket->len);
                sr_send_packet(sr, copyPacket, currPacket->len, currPacket->iface);
                free(copyPacket);

                currPacket = currPacket->next;
            }

            /* Destruir la solicitud ARP ya que se recibió la respuesta */
            sr_arpreq_destroy(&sr->cache, req);
        }
    } else {
        printf("*** -> Operación ARP desconocida %d, descartando.\n", arp_op);
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

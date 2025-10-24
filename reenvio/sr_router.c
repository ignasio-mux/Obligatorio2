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
  * - Sino, si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply 
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

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
     memcpy(ethHdr->ether_shost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     print_hdrs(copyPacket, currPacket->len);
     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
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

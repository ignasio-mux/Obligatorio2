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

  /* Obtener el cabezal ARP */
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t arp_op = ntohs(arp_hdr->ar_op);
  
  printf("* -> ARP operation: %s\n", 
         arp_op == arp_op_request ? "REQUEST" : 
         arp_op == arp_op_reply ? "REPLY" : "UNKNOWN");
  
  if (arp_op == arp_op_request) {
    printf("* -> Processing ARP REQUEST\n");
    
    /* Verificar si la solicitud es para una de nuestras interfaces */
    struct sr_if *iface = sr_get_interface(sr, interface);
    if (!iface) {
      printf("* -> Interface not found: %s\n", interface);
      return;
    }
    
    /* Verificar si la IP solicitada coincide con alguna de nuestras interfaces */
    struct sr_if *curr_iface = sr->if_list;
    struct sr_if *target_iface = NULL;
    
    while (curr_iface) {
      if (curr_iface->ip == arp_hdr->ar_tip) {
        target_iface = curr_iface;
        break;
      }
      curr_iface = curr_iface->next;
    }
    
    if (target_iface) {
      printf("* -> ARP request is for our IP: ");
      print_addr_ip_int(arp_hdr->ar_tip);
      printf("\n");
      
      /* Responder con ARP reply */
      sr_arp_reply_send(sr, arp_hdr->ar_sip, arp_hdr->ar_sha, target_iface);
    } else {
      printf("* -> ARP request is not for us, ignoring\n");
    }
    
  } else if (arp_op == arp_op_reply) {
    printf("* -> Processing ARP REPLY\n");
    
    /* Agregar el mapeo IP->MAC a la caché ARP */
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    
    if (req) {
      printf("* -> Found pending ARP request, sending queued packets\n");
      
      /* Obtener la interfaz por la que llegó el paquete */
      struct sr_if *iface = sr_get_interface(sr, interface);
      if (iface) {
        /* Enviar todos los paquetes pendientes */
        sr_arp_reply_send_pending_packets(sr, req, iface->addr, arp_hdr->ar_sha, iface);
        
        /* Limpiar la solicitud ARP */
        sr_arpreq_destroy(&sr->cache, req);
      }
    } else {
      printf("* -> No pending ARP request found for this IP\n");
    }
    
  } else {
    printf("* -> Unknown ARP operation: %d\n", arp_op);
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

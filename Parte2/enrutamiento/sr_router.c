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
 
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface);

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
 
     /* Inicializa el subsistema RIP */
     sr_rip_init(sr);
 
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
  assert(sr);
  assert(ipPacket);

  struct sr_rt *route = sr_find_lpm_entry(sr, ipDst);
  if (!route) {
    Debug("ICMP error not sent: no route to host.");
    return;
  }

  struct sr_if *out_iface = sr_get_interface(sr, route->interface);
  if (!out_iface) {
    Debug("ICMP error not sent: interface %s not found.", route->interface);
    return;
  }

  const unsigned int ip_hdr_len = sizeof(sr_ip_hdr_t);
  const unsigned int icmp_len = sizeof(sr_icmp_t3_hdr_t);
  const unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + ip_hdr_len + icmp_len;

  uint8_t *buf = (uint8_t *)malloc(packet_len);
  if (!buf) {
    fprintf(stderr, "Memory allocation failed while creating ICMP error packet\n");
    return;
  }
  memset(buf, 0, packet_len);

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);

  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;

  sr_ip_hdr_t *original_ip = (sr_ip_hdr_t *)ipPacket;
  memset(icmp_hdr->data, 0, ICMP_DATA_SIZE);
  uint16_t original_len = ntohs(original_ip->ip_len);
  if (original_len > ICMP_DATA_SIZE) {
    original_len = ICMP_DATA_SIZE;
  }
  memcpy(icmp_hdr->data, ipPacket, original_len);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);

  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = ip_hdr_len / 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(ip_hdr_len + icmp_len);
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = out_iface->ip;
  ip_hdr->ip_dst = ipDst;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);

  memcpy(eth->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_ip);

  uint32_t next_hop_ip = (route->gw.s_addr != htonl(0)) ? route->gw.s_addr : ipDst;
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

  if (arp_entry) {
    memcpy(eth->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, buf, packet_len, out_iface->name);
    free(arp_entry);
    free(buf);
  } else {
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache),
                                                 next_hop_ip,
                                                 buf,
                                                 packet_len,
                                                 out_iface->name);
    if (req) {
      handle_arpreq(sr, req);
    }
    free(buf);
  }
 } /* -- sr_send_icmp_error_packet -- */
 
 void sr_handle_ip_packet(struct sr_instance *sr,
         uint8_t *packet /* lent */,
         unsigned int len,
         uint8_t *srcAddr,
         uint8_t *destAddr,
         char *interface /* lent */,
         sr_ethernet_hdr_t *eHdr) {
 
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    Debug("IP packet too small, dropping.");
    return;
  }

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t ip_header_len = ip_hdr->ip_hl * 4;
  if (len < sizeof(sr_ethernet_hdr_t) + ip_header_len) {
    Debug("IP header length mismatch, dropping.");
    return;
  }

  uint32_t dst_ip = ip_hdr->ip_dst;
  uint32_t src_ip = ip_hdr->ip_src;
  int packet_for_router = 0;
  struct sr_if *iface_iter = sr->if_list;
  struct sr_if *incoming_iface = sr_get_interface(sr, interface);
  struct sr_if *destination_iface = NULL;

  while (iface_iter) {
    if (iface_iter->ip == dst_ip) {
      packet_for_router = 1;
      destination_iface = iface_iter;
      break;
    }
    iface_iter = iface_iter->next;
  }

  int is_rip_multicast = (dst_ip == RIP_IP);

  /* Handle packets destined to the router (including RIP) */
  if (packet_for_router || is_rip_multicast) {
    if (ip_hdr->ip_p == ip_protocol_icmp && !is_rip_multicast) {
      if (len >= sizeof(sr_ethernet_hdr_t) + ip_header_len + sizeof(sr_icmp_hdr_t)) {
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + ip_header_len);
        if (icmp_hdr->icmp_type == 8) { /* Echo request */
          unsigned int icmp_len = len - sizeof(sr_ethernet_hdr_t) - ip_header_len;
          uint8_t *reply = (uint8_t *)malloc(len);
          if (!reply) {
            fprintf(stderr, "Failed to allocate echo reply buffer\n");
            return;
          }

          memcpy(reply, packet, len);
          sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply;
          sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
          sr_icmp_hdr_t *reply_icmp = (sr_icmp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t) + ip_header_len);

          struct sr_if *out_iface = destination_iface ? destination_iface : incoming_iface;
          if (!out_iface) {
            free(reply);
            return;
          }

          memcpy(reply_eth->ether_dhost, srcAddr, ETHER_ADDR_LEN);
          memcpy(reply_eth->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

          reply_ip->ip_ttl = INIT_TTL;
          reply_ip->ip_dst = reply_ip->ip_src;
          reply_ip->ip_src = out_iface->ip;
          reply_ip->ip_sum = 0;
          reply_ip->ip_sum = cksum(reply_ip, ip_header_len);

          reply_icmp->icmp_type = 0;
          reply_icmp->icmp_code = 0;
          reply_icmp->icmp_sum = 0;
          reply_icmp->icmp_sum = cksum(reply_icmp, icmp_len);

          sr_send_packet(sr, reply, len, out_iface->name);
          free(reply);
          return;
        }
      }
    }

    if (ip_hdr->ip_p == ip_protocol_udp) {
      if (len < sizeof(sr_ethernet_hdr_t) + ip_header_len + sizeof(struct sr_udp_hdr)) {
        return;
      }

      struct sr_udp_hdr *udp_hdr = (struct sr_udp_hdr *)(packet + sizeof(sr_ethernet_hdr_t) + ip_header_len);
      uint16_t dst_port = ntohs(udp_hdr->dst_port);

      if (dst_port == RIP_PORT && (packet_for_router || is_rip_multicast)) {
        unsigned int udp_off = sizeof(sr_ethernet_hdr_t) + ip_header_len;
        unsigned int rip_off = udp_off + sizeof(struct sr_udp_hdr);
        unsigned int rip_len = ntohs(udp_hdr->length) - sizeof(struct sr_udp_hdr);
        if (rip_off + rip_len <= len) {
          sr_handle_rip_packet(sr,
                               packet,
                               len,
                               sizeof(sr_ethernet_hdr_t),
                               rip_off,
                               rip_len,
                               interface);
        }
        return;
      }

      if (packet_for_router) {
        sr_send_icmp_error_packet(3, 3, sr, src_ip, (uint8_t *)ip_hdr);
        return;
      }
    } else if (packet_for_router && (ip_hdr->ip_p == 6 || ip_hdr->ip_p == ip_protocol_icmp)) {
      if (ip_hdr->ip_p != ip_protocol_icmp) {
        sr_send_icmp_error_packet(3, 3, sr, src_ip, (uint8_t *)ip_hdr);
      }
      return;
    } else if (packet_for_router) {
      sr_send_icmp_error_packet(3, 3, sr, src_ip, (uint8_t *)ip_hdr);
      return;
    }
  }

  /* Forwarding path */
  if (ip_hdr->ip_ttl <= 1) {
    sr_send_icmp_error_packet(11, 0, sr, src_ip, (uint8_t *)ip_hdr);
    return;
  }

  struct sr_rt *route = sr_find_lpm_entry(sr, dst_ip);
  if (!route) {
    sr_send_icmp_error_packet(3, 0, sr, src_ip, (uint8_t *)ip_hdr);
    return;
  }

  struct sr_if *out_iface = sr_get_interface(sr, route->interface);
  if (!out_iface) {
    Debug("Route interface %s not found, dropping packet.", route->interface);
    return;
  }

  uint8_t *forward_packet = (uint8_t *)malloc(len);
  if (!forward_packet) {
    fprintf(stderr, "Failed to allocate packet for forwarding\n");
    return;
  }
  memcpy(forward_packet, packet, len);

  sr_ethernet_hdr_t *f_eth = (sr_ethernet_hdr_t *)forward_packet;
  sr_ip_hdr_t *f_ip = (sr_ip_hdr_t *)(forward_packet + sizeof(sr_ethernet_hdr_t));

  f_ip->ip_ttl -= 1;
  f_ip->ip_sum = 0;
  f_ip->ip_sum = cksum(f_ip, f_ip->ip_hl * 4);

  memcpy(f_eth->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  f_eth->ether_type = htons(ethertype_ip);

  uint32_t next_hop_ip = (route->gw.s_addr != htonl(0)) ? route->gw.s_addr : dst_ip;
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

  if (arp_entry) {
    memcpy(f_eth->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, forward_packet, len, out_iface->name);
    free(arp_entry);
    free(forward_packet);
  } else {
    memset(f_eth->ether_dhost, 0, ETHER_ADDR_LEN);
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache),
                                                 next_hop_ip,
                                                 forward_packet,
                                                 len,
                                                 out_iface->name);
    if (req) {
      handle_arpreq(sr, req);
    }
    free(forward_packet);
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
 
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    Debug("ARP packet too short, ignoring.");
    return;
  }

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t opcode = ntohs(arp_hdr->ar_op);
  struct sr_if *recv_iface = sr_get_interface(sr, interface);

  if (!recv_iface) {
    Debug("Received ARP on unknown interface %s", interface);
    return;
  }

  struct sr_arpreq *pending = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
  if (pending) {
    sr_arp_reply_send_pending_packets(sr, pending, arp_hdr->ar_sha, recv_iface->addr, recv_iface);
    sr_arpreq_destroy(&(sr->cache), pending);
  }

  if (opcode == arp_op_request) {
    struct sr_if *target_iface = sr_get_interface_given_ip(sr, arp_hdr->ar_tip);
    if (!target_iface) {
      Debug("ARP request not for this router.");
      return;
    }

    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *reply_buf = (uint8_t *)malloc(reply_len);
    if (!reply_buf) {
      fprintf(stderr, "Failed to allocate ARP reply buffer\n");
      return;
    }

    sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply_buf;
    sr_arp_hdr_t *reply_arp = (sr_arp_hdr_t *)(reply_buf + sizeof(sr_ethernet_hdr_t));

    memcpy(reply_eth->ether_shost, target_iface->addr, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_arp);

    reply_arp->ar_hrd = htons(arp_hrd_ethernet);
    reply_arp->ar_pro = htons(ethertype_ip);
    reply_arp->ar_hln = ETHER_ADDR_LEN;
    reply_arp->ar_pln = 4;
    reply_arp->ar_op = htons(arp_op_reply);
    memcpy(reply_arp->ar_sha, target_iface->addr, ETHER_ADDR_LEN);
    reply_arp->ar_sip = target_iface->ip;
    memcpy(reply_arp->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_arp->ar_tip = arp_hdr->ar_sip;

    sr_send_packet(sr, reply_buf, reply_len, target_iface->name);
    free(reply_buf);
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
 
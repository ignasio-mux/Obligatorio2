# Conceptos Completos - Parte 2: RIPv2

## 1. DESTINO DE PAQUETES RIPv2

### 1.1 Dirección IP Multicast

```16:16:Parte2/enrutamiento/sr_rip.h
#define RIP_IP 0xE0000009  /* 224.0.0.9 - RIPv2 multicast address */
```

- **IP Destino**: `224.0.0.9` (RIPv2 multicast address)
- **Formato**: `0xE0000009` en host byte order
- **Propósito**: Todos los routers RIPv2 escuchan en esta dirección
- **Alcance**: Solo en la red local (TTL=1, no se reenvía)

### 1.2 Dirección MAC Multicast

```28:29:Parte2/enrutamiento/sr_rip.c
/* Dirección MAC de multicast para los paquetes RIP */
uint8_t rip_multicast_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x09};
```

- **MAC Destino**: `01:00:5E:00:00:09`
- **Formato**: 
  - `01:00:5E` = Prefijo de multicast Ethernet
  - `00:00:09` = Últimos 23 bits de `224.0.0.9`
- **Conversión IP→MAC**: Los últimos 23 bits de la IP multicast se mapean a los últimos 23 bits de la MAC

**Mapeo IP Multicast → MAC Multicast:**
```
IP:  224.0.0.9  = 0xE0000009
     └─┬─┘ └─┬─┘
       │     └─→ Últimos 23 bits → MAC
       └─→ Clase D (multicast)

MAC: 01:00:5E:00:00:09
     └─┬─┘ └─────┬─────┘
       │         └─→ Últimos 23 bits de IP
       └─→ Prefijo multicast Ethernet
```

### 1.3 Uso de Multicast vs Unicast

```286:301:Parte2/enrutamiento/sr_rip.c
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
```

**Multicast (224.0.0.9)**:
- Usado para: Actualizaciones periódicas, triggered updates, requests iniciales
- Ventaja: No requiere ARP (MAC conocida)
- Alcance: Solo red local (TTL=1)

**Unicast**:
- Usado para: Respuestas a REQUEST específicos
- Requiere: ARP lookup para obtener MAC destino
- Ventaja: Puede enviarse a un router específico

---

## 2. REQUESTS INICIALES (Poblar Tabla de Enrutamiento)

### 2.1 Cuándo se Envían

```399:478:Parte2/enrutamiento/sr_rip.c
void* sr_rip_send_requests(void* arg) {
    sleep(3); // Esperar a que se inicialice todo
    struct sr_instance* sr = arg;
    struct sr_if* interface = sr->if_list;
    
    // Se envia un Request RIP por cada interfaz:
    while (interface != NULL) {
        ...
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
```

- **Momento**: Al iniciar el router (después de 3 segundos de espera)
- **Frecuencia**: Una vez por cada interfaz al inicio
- **Destino**: Multicast `224.0.0.9`
- **Formato**: Una entrada especial con `family_identifier = 0` y `metric = 16`

### 2.2 Formato del REQUEST

**Entrada especial para solicitar tabla completa:**
- `family_identifier = 0` → Solicita toda la tabla
- `ip = 0.0.0.0`
- `mask = 0.0.0.0`
- `metric = 16` (INFINITY)

### 2.3 Procesamiento de REQUEST

```214:219:Parte2/enrutamiento/sr_rip.c
    if (rip_packet->command == RIP_COMMAND_REQUEST){
        struct sr_if* in_face = sr_get_interface(sr, in_ifname);
        sr_rip_send_response(sr, in_face, dest_ip);
        printf("Respuesta RIP enviada\n");
        return;
    }
```

- Cuando un router recibe un REQUEST, responde inmediatamente con su tabla completa
- La respuesta puede ser unicast (si el REQUEST venía de una IP específica) o multicast

---

## 3. CHECKSUM UDP

### 3.1 Cálculo del Checksum UDP

```389:392:Parte2/enrutamiento/sr_rip.c
    /* Checksum UDP */
    uint8_t* udp_payload = (uint8_t*)rip_packet;
    udp_hdr->checksum = 0;
    udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, udp_payload);
```

**Características del checksum UDP:**
- **Incluye**: Pseudo-header IP + Header UDP + Payload (datos RIP)
- **Pseudo-header IP**: IP origen, IP destino, protocolo (UDP=17), longitud UDP
- **Opcional**: Si el checksum es 0, significa "no checksum" (pero RIP lo calcula)

**Proceso:**
1. Poner `udp_hdr->checksum = 0`
2. Calcular checksum sobre: pseudo-header + UDP header + payload
3. Asignar resultado a `udp_hdr->checksum`

### 3.2 Validación

El checksum UDP se valida cuando se recibe un paquete RIP (aunque no se muestra explícitamente en el código de manejo, es responsabilidad de la pila de red).

---

## 4. RUTAS A ENUNCIAR

### 4.1 Selección de Rutas

```336:377:Parte2/enrutamiento/sr_rip.c
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
```

**Rutas que se incluyen:**
- **Todas las rutas** de la tabla de enrutamiento (hasta máximo 25)
- **Rutas directamente conectadas**: Con métrica del costo del enlace
- **Rutas aprendidas**: Con métrica calculada

### 4.2 Modificaciones por Split Horizon con Poisoned Reverse

**Split Horizon con Poisoned Reverse:**
- **Regla**: Si una ruta fue aprendida por la misma interfaz por la que se va a anunciar
- **Acción**: Anunciarla con métrica `INFINITY` (16) en lugar de su métrica real
- **Propósito**: Evitar bucles de enrutamiento

**Ejemplo:**
```
Router A aprende ruta a Red X desde Router B por interfaz eth1
Cuando Router A anuncia por eth1:
  - Sin split horizon: Anunciaría "Red X, métrica 2"
  - Con poisoned reverse: Anuncia "Red X, métrica 16 (INFINITY)"
  
Esto evita que Router B piense que puede llegar a Red X a través de Router A
```

### 4.3 Rutas Expiradas

```346:349:Parte2/enrutamiento/sr_rip.c
        /* Si la ruta es inválida (expiró por timeout), usar métrica INFINITY */
        if (rt->valid == 0) {
            metric = INFINITY;
        }
```

- Si una ruta expiró (timeout), se anuncia con métrica `INFINITY`
- Esto informa a los vecinos que la ruta ya no es válida

### 4.4 Límite de Entradas

```25:25:Parte2/enrutamiento/sr_rip.h
#define RIP_MAX_ENTRIES 25  /* Máximo de rutas en un mensaje RIP response */
```

- **Máximo**: 25 rutas por mensaje RIP
- **Razón**: Limitar tamaño del paquete UDP
- **Si hay más de 25 rutas**: Se envían múltiples mensajes (aunque no está implementado en este código)

### 4.5 Campos de la Entrada RIP

```367:373:Parte2/enrutamiento/sr_rip.c
        /* Armar la entrada RIP */
        entry->family_identifier = htons(2); /* IPv4 */
        entry->route_tag = htons(rt->route_tag);
        entry->ip = rt->dest.s_addr; /* Ya está en network byte order */
        entry->mask = rt->mask.s_addr; /* Ya está en network byte order */
        entry->next_hop = htonl(0); /* Siempre 0.0.0.0 */
        entry->metric = htonl(metric);
```

- `family_identifier = 2`: IPv4
- `route_tag`: Etiqueta de ruta (normalmente 0)
- `ip`: Dirección de red destino
- `mask`: Máscara de subred
- `next_hop = 0.0.0.0`: Siempre cero (el receptor usa la IP origen del paquete IP como next-hop)
- `metric`: Distancia (1-15, o 16 para infinito)

---

## 5. CONTEO A INFINITO (Count to Infinity)

### 5.1 ¿Qué es el Conteo a Infinito?

Es un problema de los protocolos distance-vector donde las métricas aumentan gradualmente hacia infinito cuando hay un bucle de enrutamiento.

**Ejemplo del problema:**
```
Situación inicial:
  Router A → Red X (métrica 1, directamente conectada)
  Router B → Red X vía A (métrica 2)

Si se cae el enlace A-X:
  Router A: Ya no tiene ruta directa
  Router B anuncia: "Red X, métrica 2"
  Router A piensa: "Puedo llegar vía B con métrica 3"
  Router A anuncia: "Red X, métrica 3"
  Router B piensa: "Puedo llegar vía A con métrica 4"
  ... y así hasta llegar a 16 (infinito)
```

### 5.2 Prevención en RIPv2

**1. Split Horizon con Poisoned Reverse:**
```351:357:Parte2/enrutamiento/sr_rip.c
            #if ENABLE_SPLIT_HORIZON_POISONED_REVERSE
            struct sr_if* learned_if = sr_get_interface(sr, rt->interface);
            if (learned_if && strcmp(learned_if->name, interface->name) == 0) {
                /* Split horizon con poisoned reverse: anunciar con métrica INFINITY */
                metric = INFINITY;
            }
            #endif
```

**2. Límite de Métrica:**
```21:21:Parte2/enrutamiento/sr_rip.h
#define INFINITY 16
```

- **Máximo**: 15 saltos
- **Infinito**: 16 = destino inalcanzable
- **Si métrica >= 16**: Se descarta la actualización

```116:117:Parte2/enrutamiento/sr_rip.c
    /* Si resulta >=16 descarta la actualización */
    if (nuevo_costo >= 16) return 0;
```

**3. Triggered Updates:**
- Cuando una ruta cambia, se envía actualización inmediata
- Acelera la convergencia y reduce el tiempo de bucles

### 5.3 Manejo de Métrica Infinita

```100:107:Parte2/enrutamiento/sr_rip.c
    if (costo >= 16) { 
        if (entry_in_rt != NULL && entry_in_rt->learned_from == src_ip) {
            entry_in_rt->valid = 0;
            entry_in_rt->metric = INFINITY;
            entry_in_rt->garbage_collection_time = now;
            return 1;
        } else return 0;
    }
```

- Si se recibe métrica `>= 16`:
  - Si la ruta existe y fue aprendida del mismo vecino: Marca como inválida
  - Si no: Ignora el anuncio (evita que otros routers marquen rutas como infinitas incorrectamente)

---

## 6. TTL (Time To Live)

### 6.1 TTL en Paquetes RIP

```315:315:Parte2/enrutamiento/sr_rip.c
    ip_hdr->ip_ttl = 1; /* RIP usa TTL=1 */
```

```436:436:Parte2/enrutamiento/sr_rip.c
        ip_hdr->ip_ttl = 1; /* RIP usa TTL=1 */
```

**Valor**: Siempre `TTL = 1`

**Razones:**
1. **Alcance local**: RIP solo debe propagarse en la red local
2. **Evitar reenvío**: Los routers intermedios no deben reenviar paquetes RIP
3. **Seguridad**: Previene que paquetes RIP viajen por Internet

**Comportamiento:**
- Router recibe paquete con TTL=1
- Decrementa TTL → TTL=0
- **No reenvía** el paquete (se descarta)
- Solo procesa si el destino es el router mismo o multicast local

### 6.2 Diferencia con Paquetes IP Normales

**Paquetes IP normales:**
- TTL inicial: 64 (o 128, según implementación)
- Se decrementa en cada salto
- Si TTL llega a 0: Se envía ICMP Time Exceeded

**Paquetes RIP:**
- TTL siempre = 1
- No se reenvían (solo procesamiento local)
- Alcance: Una sola red

---

## 7. RESPONSES (Unicast y Multicast)

### 7.1 Tipos de RESPONSE

**1. RESPONSE Periódico (Multicast):**
```550:550:Parte2/enrutamiento/sr_rip.c
            sr_rip_send_response(sr, interface, htonl(RIP_IP));
```

- **Destino**: `224.0.0.9` (multicast)
- **Frecuencia**: Cada 10 segundos
- **Propósito**: Anunciar rutas a todos los vecinos
- **MAC**: `01:00:5E:00:00:09` (no requiere ARP)

**2. RESPONSE a REQUEST (Puede ser Unicast):**
```214:219:Parte2/enrutamiento/sr_rip.c
    if (rip_packet->command == RIP_COMMAND_REQUEST){
        struct sr_if* in_face = sr_get_interface(sr, in_ifname);
        sr_rip_send_response(sr, in_face, dest_ip);
        printf("Respuesta RIP enviada\n");
        return;
    }
```

- **Destino**: IP del que envió el REQUEST (puede ser unicast)
- **Momento**: Inmediato al recibir REQUEST
- **MAC**: Requiere ARP lookup si es unicast

**3. RESPONSE Triggered (Multicast):**
```170:176:Parte2/enrutamiento/sr_rip.c
void sr_rip_send_triggered_update(struct sr_instance* sr) {
    struct sr_if* interface = sr->if_list;
    while (interface != NULL) {
        sr_rip_send_response(sr, interface, RIP_IP);    
        interface = interface->next;
    }
}
```

- **Destino**: `224.0.0.9` (multicast)
- **Momento**: Inmediato cuando cambia la tabla
- **Propósito**: Convergencia rápida

### 7.2 Determinación Unicast vs Multicast

```287:301:Parte2/enrutamiento/sr_rip.c
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
```

**Detección:**
- Si `ipDst & 0xF0000000 == 0xE0000000` → Es multicast (224.0.0.0/4)
- Si no → Es unicast (requiere ARP)

**Ventajas de Multicast:**
- No requiere ARP
- Más eficiente (un paquete para todos)
- Estándar RIPv2

**Ventajas de Unicast:**
- Puede enviarse a router específico
- Útil para respuestas a REQUEST

---

## 8. OTROS ELEMENTOS RELEVANTES

### 8.1 Rutas Directamente Conectadas

```488:523:Parte2/enrutamiento/sr_rip.c
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
```

**Características:**
- Se agregan automáticamente al iniciar RIP
- **Gateway**: `0.0.0.0` (directamente conectada)
- **Métrica**: Costo de la interfaz (por defecto 1)
- **learned_from**: `0` (no aprendida de vecino)
- **Valid**: Siempre válida (no expira)

### 8.2 Timeouts y Garbage Collection

```23:24:Parte2/enrutamiento/sr_rip.h
#define RIP_TIMEOUT_SEC 60
#define RIP_GARBAGE_COLLECTION_SEC 40
```

**Timeout (60 segundos):**
- Si no se recibe actualización de una ruta aprendida en 60 segundos
- Se marca como `valid = 0`
- Se pone métrica a `INFINITY`
- Se inicia garbage collection

**Garbage Collection (40 segundos adicionales):**
- Después de 40 segundos más (total 100 segundos desde última actualización)
- Se elimina la ruta de la tabla
- Se envía triggered update anunciando métrica INFINITY

```586:600:Parte2/enrutamiento/sr_rip.c
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
```

### 8.3 Actualización de Rutas

**Lógica de actualización:**

```60:166:Parte2/enrutamiento/sr_rip.c
int sr_rip_update_route(struct sr_instance* sr,
                        const struct sr_rip_entry_t* rte,
                        uint32_t src_ip,
                        const char* in_ifname)
{
    ...
    /* Calcula la nueva métrica sumando el coste del enlace de la interfaz */
    struct sr_if* in_enlace = sr_get_interface(sr,in_ifname);
    if (in_enlace == NULL) return -1;
    
    uint32_t costo_enlace = in_enlace->cost;
    uint32_t nuevo_costo = costo_enlace + costo;

    /* Si resulta >=16 descarta la actualización */
    if (nuevo_costo >= 16) return 0;

    /* Si la ruta no existe, inserta una nueva entrada en la tabla de enrutamiento */
    if (entry_in_rt == NULL){
        dest.s_addr = rte->ip;
        gw.s_addr = src_ip; 
        mask.s_addr = rte->mask;
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
        return 1;
    
    /* Si la entrada fue aprendida del mismo vecino:
    Actualiza métrica/gateway/timestamps si cambian; si no, solo refresca el timestamp */
    }else {
        if (entry_in_rt->learned_from == src_ip) {
            if (entry_in_rt->metric != nuevo_costo) entry_in_rt->metric = nuevo_costo;
            entry_in_rt->last_updated = now;
            return 1;
    
        /* Si la entrada viene de otro origen */
        } else {

            /* - Reemplaza la ruta si la nueva métrica es mejor. */
            if(entry_in_rt->metric > nuevo_costo) {
                dest.s_addr = rte->ip;
                gw.s_addr = src_ip; 
                mask.s_addr = rte->mask;
                sr_del_rt_entry(&sr->routing_table, entry_in_rt);                
                sr_add_rt_entry(sr, dest, gw, mask, in_ifname, nuevo_costo, 0, src_ip, now, 1,now);
                return 1;
            
            /* - Si la métrica es igual y el next-hop coincide, refresca la entrada.*/
            } else if (entry_in_rt->metric == nuevo_costo && entry_in_rt->gw.s_addr == src_ip) {
                entry_in_rt->last_updated = now;                
                return 1;
            /*- En caso contrario (peor métrica o diferente camino), ignora la actualización.*/    
            }else return 0;
        }
    }
    return 0;
}
```

**Casos:**
1. **Ruta nueva**: Se inserta con nueva métrica
2. **Ruta inválida**: Se revive con nueva métrica
3. **Mismo vecino**: Actualiza métrica si cambió, refresca timestamp
4. **Otro origen, mejor métrica**: Reemplaza ruta
5. **Otro origen, misma métrica, mismo gateway**: Refresca timestamp
6. **Otro origen, peor métrica**: Ignora

### 8.4 Triggered Updates

```168:177:Parte2/enrutamiento/sr_rip.c
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
```

**Cuándo se envían:**
- Cuando la tabla de rutas cambia (nueva ruta, métrica mejor, ruta expirada)
- Inmediatamente (no espera 10 segundos)
- Por todas las interfaces

**Propósito:**
- Convergencia rápida
- Notificar cambios importantes inmediatamente

### 8.5 Puerto UDP

```17:17:Parte2/enrutamiento/sr_rip.h
#define RIP_PORT 520
```

- **Puerto**: 520 (estándar RIPv2)
- **Uso**: Tanto origen como destino
- **Privilegios**: En sistemas Unix, requiere privilegios de root para bindear puerto < 1024

### 8.6 Procesamiento de Paquetes RIP

```317:325:Parte2/enrutamiento/sr_router.c
    } else if (dest_ip == htonl(RIP_IP) && ip_hdr->ip_p == ip_protocol_udp) {
        sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (udp_hdr->dst_port == RIP_PORT) {
            unsigned int ip_off = sizeof(sr_ethernet_hdr_t);
            unsigned int rip_off = ip_off + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) ;
            unsigned int rip_len = len - rip_off;
            sr_handle_rip_packet(sr, packet, len, ip_off, rip_off, rip_len, interface);
        }    
    }
```

**Detección:**
- IP destino = `224.0.0.9`
- Protocolo = UDP
- Puerto destino = 520

**Procesamiento:**
- Se extrae el payload RIP
- Se valida el paquete
- Se procesa según command (REQUEST o RESPONSE)

### 8.7 Hilos de RIP

**1. Hilo de Anuncios Periódicos:**
```482:560:Parte2/enrutamiento/sr_rip.c
void* sr_rip_periodic_advertisement(void* arg) {
    ...
    while (1) {
        struct sr_if* interface = sr->if_list;
        while (interface != NULL) {
            sr_rip_send_response(sr, interface, htonl(RIP_IP));
            interface = interface->next;
        }
        sleep(RIP_ADVERT_INTERVAL_SEC);
    }
}
```

**2. Hilo de Timeout Manager:**
```563:610:Parte2/enrutamiento/sr_rip.c
void* sr_rip_timeout_manager(void* arg) {
    struct sr_instance* sr = arg;
    
    /* Bucle periódico que espera 1 segundo entre comprobaciones */
    while (1) {
        sleep(1);
        ...
        /* Verificar timeouts y garbage collection */
    }
}
```

**3. Hilo de Requests Iniciales:**
```399:478:Parte2/enrutamiento/sr_rip.c
void* sr_rip_send_requests(void* arg) {
    sleep(3);
    ...
    /* Enviar REQUEST por cada interfaz */
}
```

### 8.8 Next-Hop en Entradas RIP

```372:372:Parte2/enrutamiento/sr_rip.c
        entry->next_hop = htonl(0); /* Siempre 0.0.0.0 */
```

- **Valor**: Siempre `0.0.0.0`
- **Razón**: El receptor usa la IP origen del paquete IP como next-hop
- **Ventaja**: Reduce tamaño del mensaje

**Cómo se determina el next-hop real:**
- El router receptor usa `ip_hdr->ip_src` como gateway
- Esto es la IP del router que envió el mensaje RIP

### 8.9 Validación de Paquetes RIP

```32:58:Parte2/enrutamiento/sr_rip.c
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
```

**Validaciones:**
1. Longitud mínima suficiente
2. Command válido (1 o 2)
3. Versión = 2
4. Campo zero = 0
5. Longitud correcta (múltiplo de tamaño de entrada)

---

## RESUMEN DE CONCEPTOS CLAVE

| Concepto | Valor/Comportamiento |
|----------|---------------------|
| **IP Multicast** | 224.0.0.9 |
| **MAC Multicast** | 01:00:5E:00:00:09 |
| **Puerto UDP** | 520 |
| **TTL IP** | 1 (solo red local) |
| **Métrica máxima** | 15 (16 = infinito) |
| **Intervalo anuncios** | 10 segundos |
| **Timeout ruta** | 60 segundos |
| **Garbage collection** | 40 segundos adicionales |
| **Máximo entradas/mensaje** | 25 |
| **Next-hop en entrada** | Siempre 0.0.0.0 |
| **Split Horizon** | Habilitado con poisoned reverse |

---

## FLUJO COMPLETO DE UN PAQUETE RIP

```
1. Construcción del paquete:
   └─► Ethernet Header
       ├─ MAC destino: 01:00:5E:00:00:09 (multicast) o ARP lookup (unicast)
       ├─ MAC origen: MAC de interfaz
       └─ ether_type: 0x0800 (IPv4)
   
   └─► IP Header
       ├─ ip_src: IP de interfaz
       ├─ ip_dst: 224.0.0.9 (multicast) o IP específica (unicast)
       ├─ ip_ttl: 1
       └─ ip_p: 17 (UDP)
   
   └─► UDP Header
       ├─ src_port: 520
       ├─ dst_port: 520
       ├─ length: tamaño UDP
       └─ checksum: calculado (pseudo-header + UDP + payload)
   
   └─► RIP Packet
       ├─ command: 1 (REQUEST) o 2 (RESPONSE)
       ├─ version: 2
       ├─ zero: 0
       └─ entries[]: hasta 25 entradas
           ├─ family_identifier: 2 (IPv4)
           ├─ route_tag: etiqueta
           ├─ ip: red destino
           ├─ mask: máscara
           ├─ next_hop: 0.0.0.0
           └─ metric: 1-15 o 16 (infinito)

2. Envío:
   └─► Multicast: Directo (MAC conocida)
   └─► Unicast: Requiere ARP lookup

3. Recepción:
   └─► Validar: IP destino, puerto UDP, formato RIP
   └─► Procesar: REQUEST → enviar RESPONSE
                RESPONSE → actualizar tabla

4. Actualización de tabla:
   └─► Calcular nueva métrica
   └─► Aplicar reglas de actualización
   └─► Si cambió: enviar triggered update
```

---

## DIFERENCIAS CLAVE: Parte 1 vs Parte 2

| Aspecto | Parte 1 | Parte 2 |
|---------|---------|---------|
| **Tabla de enrutamiento** | Estática (archivo) | Dinámica (RIP) |
| **Rutas** | Preconfiguradas | Aprendidas automáticamente |
| **Actualización** | Manual | Automática (10 seg) |
| **Métrica** | No usa | Hops (1-15, 16=infinito) |
| **Vecinos** | No hay concepto | Detecta automáticamente |
| **Convergencia** | N/A | Automática |
| **TTL en RIP** | N/A | Siempre 1 |
| **Multicast** | No usa | 224.0.0.9 |
| **UDP** | No usa | Puerto 520 |
| **Split Horizon** | N/A | Con poisoned reverse |


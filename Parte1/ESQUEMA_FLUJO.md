# Esquema de Flujo Completo - Parte 1

## FLUJO PRINCIPAL: Llegada de un Paquete

```
┌─────────────────────────────────────────────────────────────┐
│ 1. FRAMEWORK: sr_handlepacket()                             │
│    (Llamado automáticamente cuando llega un paquete)        │
│    - Recibe: trama Ethernet raw completa                    │
│    - Extrae: MAC origen, MAC destino, ether_type          │
│    - Valida: is_packet_valid()                             │
└─────────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
    ┌───────────────────┐   ┌───────────────────┐
    │ ethertype_arp     │   │ ethertype_ip      │
    │ (0x0806)          │   │ (0x0800)          │
    └───────────────────┘   └───────────────────┘
                │                       │
                │                       │
                ▼                       ▼
```

---

## FLUJO ARP: Procesamiento de Paquetes ARP

```
┌─────────────────────────────────────────────────────────────┐
│ 2. TU FUNCIÓN: sr_handle_arp_packet() ⭐                    │
│    LLAMADA POR: sr_handlepacket() (framework)              │
│                                                              │
│    Parámetros recibidos:                                    │
│    - packet: trama Ethernet completa                       │
│    - len: longitud                                          │
│    - srcAddr, destAddr: MACs                                │
│    - interface: interfaz de recepción                       │
│    - eHdr: puntero al header Ethernet                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Validar formato ARP           │
            │ - Longitud mínima             │
            │ - Hardware = Ethernet         │
            │ - Protocolo = IP               │
            └───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
    ┌───────────────────┐   ┌───────────────────┐
    │ ARP REQUEST       │   │ ARP REPLY         │
    │ (ar_op = 1)       │   │ (ar_op = 2)       │
    └───────────────────┘   └───────────────────┘
                │                       │
                │                       │
                ▼                       ▼
    ┌───────────────────┐   ┌───────────────────────────────┐
    │ ¿Es para una de   │   │ FRAMEWORK:                     │
    │ nuestras IPs?     │   │ sr_arpcache_insert()           │
    │                   │   │ - Inserta IP->MAC en caché    │
    │ Si SÍ:            │   │ - Retorna sr_arpreq si existe │
    │ Construir ARP     │   └───────────────────────────────┘
    │ Reply y enviar    │                   │
    │                   │                   ▼
    │ Si NO:            │   ┌───────────────────────────────┐
    │ Ignorar           │   │ Si hay paquetes en cola:      │
    └───────────────────┘   │ - Actualizar MACs             │
                            │ - Enviar todos los paquetes   │
                            │ - Destruir solicitud ARP      │
                            └───────────────────────────────┘
```

---

## FLUJO IP: Procesamiento de Paquetes IP

```
┌─────────────────────────────────────────────────────────────┐
│ 3. TU FUNCIÓN: sr_handle_ip_packet() ⭐                     │
│    LLAMADA POR: sr_handlepacket() (framework)                │
│                                                              │
│    Parámetros recibidos:                                    │
│    - packet: trama Ethernet completa                       │
│    - len: longitud                                          │
│    - srcAddr, destAddr: MACs                                │
│    - interface: interfaz de recepción                       │
│    - eHdr: puntero al header Ethernet                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Extraer header IP             │
            │ ip_hdr = packet + 14          │
            └───────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ ¿Paquete para el router?      │
            │ is_packet_for_me()            │
            └───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
               SÍ                      NO
                │                       │
                │                       │
                ▼                       ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │ PROCESAMIENTO LOCAL   │   │ REENVÍO DE PAQUETE     │
    │                       │   │                       │
    │ Casos:                │   │ 1. Buscar ruta (LPM)  │
    │                       │   │    sr_find_lpm_entry()│
    │ - ICMP Echo Request   │   │                       │
    │   (tipo 8)            │   │ 2. Verificar TTL      │
    │                       │   │                       │
    │ - UDP/TCP para router│   │ 3. Decrementar TTL     │
    │                       │   │    Recalcular checksum│
    │ - Otros: descartar    │   │                       │
    └───────────────────────┘   │ 4. Determinar next_hop │
                │               │                       │
                │               │ 5. Buscar MAC en ARP  │
                │               │    sr_arpcache_       │
                │               │    lookup()           │
                │               └───────────────────────┘
                │                           │
                │               ┌───────────┴───────────┐
                │              SÍ                      NO
                │               │                       │
                │               │                       │
                │               ▼                       ▼
                │   ┌───────────────────┐   ┌───────────────────┐
                │   │ Actualizar MACs   │   │ Copiar paquete   │
                │   │ Enviar paquete    │   │ Encolar en ARP   │
                │   └───────────────────┘   │ sr_arpcache_     │
                │                           │ queuereq()        │
                │                           │                   │
                │                           │ LLAMAR:          │
                │                           │ handle_arpreq() ⭐│
                │                           └───────────────────┘
                │
                ▼
    ┌───────────────────────────────────────────┐
    │ CASO 1: ICMP Echo Request (tipo 8)        │
    │                                           │
    │ LLAMAR:                                   │
    │ sr_send_icmp_error_packet(0,0,...) ⭐    │
    │ (Echo Reply)                              │
    └───────────────────────────────────────────┘
                │
                ▼
    ┌───────────────────────────────────────────┐
    │ CASO 2: UDP/TCP para router               │
    │                                           │
    │ LLAMAR:                                   │
    │ sr_send_icmp_error_packet(3,3,...) ⭐     │
    │ (Port Unreachable)                        │
    └───────────────────────────────────────────┘
```

---

## FLUJO: Cuando NO hay MAC en caché ARP

```
┌─────────────────────────────────────────────────────────────┐
│ 4. TU FUNCIÓN: handle_arpreq() ⭐                           │
│    LLAMADA POR:                                             │
│    - sr_handle_ip_packet() ⭐ (cuando no hay MAC)          │
│    - sr_arpcache_sweepreqs() (hilo de timeout cada 1 seg) │
│                                                              │
│    Parámetros recibidos:                                    │
│    - sr: instancia del router                               │
│    - req: solicitud ARP con paquetes en cola               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ ¿Primera solicitud?           │
            │ (req->sent == 0)              │
            └───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
               SÍ                      NO
                │                       │
                │                       ▼
                │           ┌───────────────────────────────┐
                │           │ Calcular tiempo desde        │
                │           │ último envío                 │
                │           │ difftime(now, req->sent)     │
                │           └───────────────────────────────┘
                │                       │
                │                       ▼
                │           ┌───────────────────────────────┐
                │           │ ¿Pasó >= 1 segundo?           │
                │           │ (Rate limiting)                │
                │           └───────────────────────────────┘
                │                       │
                │           ┌───────────┴───────────┐
                │          NO                        SÍ
                │           │                         │
                │           │                         ▼
                │           │             ┌───────────────────────────────┐
                │           │             │ ¿Intentos < 5?               │
                │           │             └───────────────────────────────┘
                │           │                         │
                │           │             ┌───────────┴───────────┐
                │           │            NO                        SÍ
                │           │             │                         │
                │           │             │                         ▼
                │           │             │             ┌───────────────────────────────┐
                │           │             │             │ LLAMAR:                         │
                │           │             │             │ sr_arp_request_send() ⭐        │
                │           │             │             │ Actualizar:                    │
                │           │             │             │ - req->sent = now             │
                │           │             │             │ - req->times_sent++           │
                │           │             │             └───────────────────────────────┘
                │           │             │
                │           │             ▼
                │           │ ┌───────────────────────────────┐
                │           │ │ LLAMAR:                        │
                │           │ │ host_unreachable() ⭐          │
                │           │ │ Destruir solicitud ARP         │
                │           │ └───────────────────────────────┘
                │           │
                ▼           │
    ┌───────────────────────┐
    │ LLAMAR:               │
    │ sr_arp_request_send() ⭐│
    │ Actualizar:            │
    │ - req->sent = now      │
    │ - req->times_sent = 1  │
    └───────────────────────┘
```

---

## FLUJO: Envío de Solicitud ARP

```
┌─────────────────────────────────────────────────────────────┐
│ 5. TU FUNCIÓN: sr_arp_request_send() ⭐                     │
│    LLAMADA POR: handle_arpreq() ⭐                           │
│                                                              │
│    Parámetros recibidos:                                    │
│    - sr: instancia del router                               │
│    - ip: IP objetivo                                         │
│    - iface: interfaz de salida                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Buscar ruta (LPM)             │
            │ sr_find_lpm_entry()           │
            └───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
               NO                      SÍ
                │                       │
                │                       ▼
                │           ┌───────────────────────────────┐
                │           │ Obtener interfaz             │
                │           │ sr_get_interface()          │
                │           └───────────────────────────────┘
                │                       │
                │                       ▼
                │           ┌───────────────────────────────┐
                │           │ Construir ARP Request:        │
                │           │ - MAC destino: Broadcast      │
                │           │ - MAC origen: Interfaz        │
                │           │ - ar_op = 1 (Request)         │
                │           │ - ar_tip = IP objetivo        │
                │           └───────────────────────────────┘
                │                       │
                │                       ▼
                │           ┌───────────────────────────────┐
                │           │ Enviar ARP Request            │
                │           │ sr_send_packet()              │
                │           └───────────────────────────────┘
                │
                ▼
        (Retornar)
```

---

## FLUJO: ARP Falló (5 Intentos)

```
┌─────────────────────────────────────────────────────────────┐
│ 6. TU FUNCIÓN: host_unreachable() ⭐                         │
│    LLAMADA POR: handle_arpreq() ⭐                           │
│    (cuando req->times_sent >= 5)                            │
│                                                              │
│    Parámetros recibidos:                                    │
│    - sr: instancia del router                               │
│    - req: solicitud ARP con paquetes en cola               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Iterar sobre req->packets     │
            │ (todos los paquetes en cola)  │
            └───────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Para cada paquete:            │
            │ 1. Extraer IP origen          │
            │    del header IP              │
            │ 2. LLAMAR:                    │
            │    sr_send_icmp_error_packet  │
            │    (3,1,...) ⭐                │
            │    (Host Unreachable)         │
            └───────────────────────────────┘
```

---

## FLUJO: Construcción y Envío de Mensajes ICMP

```
┌─────────────────────────────────────────────────────────────┐
│ 7. TU FUNCIÓN: sr_send_icmp_error_packet() ⭐               │
│    LLAMADA POR:                                             │
│    - sr_handle_ip_packet() ⭐ (varios casos)               │
│    - host_unreachable() ⭐                                   │
│                                                              │
│    Parámetros recibidos:                                    │
│    - type: tipo ICMP (0, 3, 11)                             │
│    - code: código ICMP (0, 1, 3)                            │
│    - sr: instancia del router                               │
│    - ipDst: IP destino del mensaje ICMP                    │
│    - ipPacket: paquete IP original (para copiar datos)     │
└─────────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
    ┌───────────────────┐   ┌───────────────────┐
    │ type 3 o 11       │   │ type 0             │
    │ (Error)           │   │ (Echo Reply)       │
    └───────────────────┘   └───────────────────┘
                │                       │
                │                       │
                ▼                       ▼
    ┌───────────────────┐   ┌───────────────────┐
    │ Construir ICMP    │   │ Construir ICMP    │
    │ Type 3/11:        │   │ Echo Reply:       │
    │ - Copiar 28 bytes │   │ - Copiar 60 bytes │
    │   del original    │   │   del original    │
    └───────────────────┘   └───────────────────┘
                │                       │
                └───────────┬───────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Construir header IP:          │
            │ - ip_p = 1 (ICMP)             │
            │ - ip_src = IP del router      │
            │ - ip_dst = ipDst              │
            │ - Calcular checksum IP        │
            └───────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Construir header Ethernet:    │
            │ - ether_type = 0x0800         │
            │ - ether_shost = MAC router    │
            └───────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Buscar ruta (LPM)             │
            │ sr_find_lpm_entry()           │
            └───────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Buscar MAC destino en ARP     │
            │ sr_arpcache_lookup()          │
            └───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
               SÍ                      NO
                │                       │
                │                       │
                ▼                       ▼
    ┌───────────────────┐   ┌───────────────────┐
    │ Actualizar MAC    │   │ Encolar paquete   │
    │ destino           │   │ ICMP en ARP       │
    │ Enviar paquete    │   │ sr_arpcache_      │
    │ ICMP              │   │ queuereq()        │
    │                   │   │                   │
    │                   │   │ LLAMAR:            │
    │                   │   │ handle_arpreq() ⭐ │
    └───────────────────┘   └───────────────────┘
```

---

## CASOS ESPECÍFICOS: Cuándo se llama sr_send_icmp_error_packet()

### Caso 1: No hay ruta hacia el destino
```
sr_handlepacket() (framework)
  └─► sr_handle_ip_packet() ⭐
      └─► sr_find_lpm_entry() retorna NULL
          └─► LLAMAR: sr_send_icmp_error_packet(3,0,...) ⭐
              (Network Unreachable)
```

### Caso 2: TTL expirado
```
sr_handlepacket() (framework)
  └─► sr_handle_ip_packet() ⭐
      └─► ip_hdr->ip_ttl <= 1
          └─► LLAMAR: sr_send_icmp_error_packet(11,0,...) ⭐
              (Time Exceeded)
```

### Caso 3: ARP falla después de 5 intentos
```
sr_arpcache_sweepreqs() (hilo timeout, cada 1 seg)
  └─► handle_arpreq() ⭐
      └─► req->times_sent >= 5
          └─► LLAMAR: host_unreachable() ⭐
              └─► Para cada paquete en cola:
                  └─► LLAMAR: sr_send_icmp_error_packet(3,1,...) ⭐
                      (Host Unreachable)
```

### Caso 4: ICMP Echo Request recibido
```
sr_handlepacket() (framework)
  └─► sr_handle_ip_packet() ⭐
      └─► Paquete para router
          └─► ICMP tipo 8 (Echo Request)
              └─► LLAMAR: sr_send_icmp_error_packet(0,0,...) ⭐
                  (Echo Reply)
```

### Caso 5: UDP/TCP para router sin servicio
```
sr_handlepacket() (framework)
  └─► sr_handle_ip_packet() ⭐
      └─► Paquete para router
          └─► Protocolo UDP o TCP
              └─► LLAMAR: sr_send_icmp_error_packet(3,3,...) ⭐
                  (Port Unreachable)
```

---

## FLUJO COMPLETO: Ejemplo - Paquete IP que necesita reenvío

```
1. Paquete IP llega al router
   │
   ▼
2. FRAMEWORK: sr_handlepacket()
   │
   ▼
3. TU FUNCIÓN: sr_handle_ip_packet() ⭐
   │ - Extrae header IP
   │ - Verifica que NO es para el router
   │
   ▼
4. Buscar ruta (LPM)
   │ - sr_find_lpm_entry()
   │
   ▼
5. ¿Ruta encontrada?
   │
   ├─ NO ──► LLAMAR: sr_send_icmp_error_packet(3,0,...) ⭐
   │         (Network Unreachable)
   │
   └─ SÍ ──► Verificar TTL
             │
             ├─ TTL <= 1 ──► LLAMAR: sr_send_icmp_error_packet(11,0,...) ⭐
             │              (Time Exceeded)
             │
             └─ TTL OK ──► Decrementar TTL, recalcular checksum
                           │
                           ▼
                    Determinar next_hop_ip
                           │
                           ▼
                    Buscar MAC en caché ARP
                           │
                           ├─ MAC encontrada ──► Actualizar MACs y enviar
                           │
                           └─ MAC NO encontrada
                              │
                              ▼
                              Copiar paquete y encolar en ARP
                              │
                              ▼
                              LLAMAR: handle_arpreq() ⭐
                              │
                              ├─ Primera vez ──► LLAMAR: sr_arp_request_send() ⭐
                              │
                              └─ Reintentos
                                 │
                                 ├─ Intentos < 5 ──► LLAMAR: sr_arp_request_send() ⭐
                                 │
                                 └─ Intentos >= 5 ──► LLAMAR: host_unreachable() ⭐
                                                     │
                                                     └─► Para cada paquete:
                                                         LLAMAR: sr_send_icmp_error_packet(3,1,...) ⭐
```

---

## FLUJO COMPLETO: Ejemplo - ARP Reply recibido

```
1. ARP Reply llega al router
   │
   ▼
2. FRAMEWORK: sr_handlepacket()
   │
   ▼
3. TU FUNCIÓN: sr_handle_arp_packet() ⭐
   │ - Detecta ar_op = 2 (Reply)
   │
   ▼
4. FRAMEWORK: sr_arpcache_insert()
   │ - Inserta IP->MAC en caché
   │ - Retorna sr_arpreq si hay paquetes esperando
   │
   ▼
5. ¿Hay paquetes en cola? (req != NULL)
   │
   └─ SÍ ──► Para cada paquete en cola:
             │ - Actualizar MAC destino
             │ - Actualizar MAC origen
             │ - Enviar paquete
             │
             └─► Destruir solicitud ARP
```

---

## FLUJO COMPLETO: Ejemplo - ARP Request recibido

```
1. ARP Request llega al router
   │
   ▼
2. FRAMEWORK: sr_handlepacket()
   │
   ▼
3. TU FUNCIÓN: sr_handle_arp_packet() ⭐
   │ - Detecta ar_op = 1 (Request)
   │
   ▼
4. ¿Es para una de nuestras IPs?
   │
   ├─ NO ──► Ignorar paquete
   │
   └─ SÍ ──► Construir ARP Reply:
             │ - MAC destino = MAC del solicitante
             │ - MAC origen = MAC de nuestra interfaz
             │ - ar_op = 2 (Reply)
             │ - Enviar ARP Reply
```

---

## RESUMEN: Quién llama a tus funciones ⭐

| Tu Función | Llamada Por |
|------------|-------------|
| **sr_handle_arp_packet()** | `sr_handlepacket()` (framework) cuando `ethertype == 0x0806` |
| **sr_handle_ip_packet()** | `sr_handlepacket()` (framework) cuando `ethertype == 0x0800` |
| **sr_send_icmp_error_packet()** | - `sr_handle_ip_packet()` ⭐ (casos: no ruta, TTL, echo, UDP/TCP)<br>- `host_unreachable()` ⭐ (cuando ARP falla) |
| **handle_arpreq()** | - `sr_handle_ip_packet()` ⭐ (cuando no hay MAC)<br>- `sr_arpcache_sweepreqs()` (hilo timeout cada 1 seg) |
| **sr_arp_request_send()** | `handle_arpreq()` ⭐ (primera vez o reintentos) |
| **host_unreachable()** | `handle_arpreq()` ⭐ (cuando `times_sent >= 5`) |

---

## HILO ASÍNCRONO: Timeout de ARP

```
┌─────────────────────────────────────────────────────────────┐
│ FRAMEWORK: sr_arpcache_timeout()                           │
│ (Hilo ejecutándose continuamente)                          │
│                                                              │
│ Cada 1 segundo:                                             │
│ 1. Expira entradas ARP > 15 segundos                      │
│ 2. LLAMAR: sr_arpcache_sweepreqs()                         │
│    └─► Para cada solicitud ARP pendiente:                  │
│        └─► LLAMAR: handle_arpreq() ⭐                      │
│            (para verificar si debe reintentar)             │
└─────────────────────────────────────────────────────────────┘
```

---

## PUNTOS CLAVE DEL FLUJO

1. **Entrada única**: Todo comienza en `sr_handlepacket()` (framework)
2. **Tu código controla**: El procesamiento de ARP e IP
3. **ARP resuelve MACs**: Cuando IP necesita reenviar pero no tiene MAC
4. **ICMP reporta errores**: En múltiples escenarios de fallo
5. **Cola de paquetes**: Los paquetes esperan mientras se resuelve ARP
6. **Reintentos automáticos**: ARP se reintenta hasta 5 veces con rate limiting
7. **Hilo de timeout**: Verifica periódicamente solicitudes ARP pendientes

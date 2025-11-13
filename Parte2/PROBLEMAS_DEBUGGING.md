# Problemas Enfrentados y Técnicas de Debugging - Parte 2

## Resumen Ejecutivo

Durante el desarrollo de la Parte 2 (implementación de RIPv2), enfrentamos varios desafíos técnicos relacionados con el manejo de protocolos de red, conversión de byte order, sincronización de threads, y depuración de sistemas distribuidos. Este documento resume los problemas principales y las herramientas de debugging utilizadas para resolverlos.

---

## 1. Problemas de Compilación y Arquitectura

### Problema 1.1: Incompatibilidad de Arquitectura
**Descripción**: Error `sha1.o: file not recognized: File format not recognized` al compilar en la VM Linux después de haber compilado previamente en Mac (Darwin).

**Causa**: Los archivos objeto (`.o`) compilados en una arquitectura (Darwin/x86_64) no son compatibles con otra (Linux/x86_64), aunque ambas sean x86_64, debido a diferencias en el formato de binarios.

**Solución**: 
```bash
rm -f *.o
make clean
make
```

**Lección aprendida**: Siempre compilar en el entorno objetivo. No transferir archivos objeto entre sistemas diferentes.

---

## 2. Problemas de ARP (Address Resolution Protocol)

### Problema 2.1: Router no aprendía direcciones MAC
**Síntoma**: Ping desde cliente a router directamente conectado resultaba en 100% packet loss, aunque el router recibía y procesaba los paquetes ICMP echo request.

**Análisis inicial**:
- El router recibía los paquetes ICMP echo request correctamente
- El router generaba respuestas ICMP echo reply
- Pero las respuestas nunca llegaban al cliente

**Debugging utilizado**:
```c
printf("*** -> DEBUG: Checking ARP cache for src IP\n");
printf("*** -> DEBUG: No ARP entry found, inserting new one\n");
printf("*** -> Learned MAC address for IP ");
print_addr_ip_int(htonl(src_ip));
printf(" from incoming packet\n");
```

**Causa raíz**: El router no estaba aprendiendo las direcciones MAC de los remitentes cuando recibía paquetes IP. Solo aprendía MACs cuando recibía respuestas ARP explícitas.

**Solución**: Agregar aprendizaje proactivo de MACs en `sr_handle_ip_packet`:
```c
/* Actualizar caché ARP con la MAC origen del paquete */
struct sr_arpentry *existing_entry = sr_arpcache_lookup(&sr->cache, src_ip);
if (!existing_entry) {
    sr_arpcache_insert(&sr->cache, srcAddr, src_ip);
} else {
    if (memcmp(existing_entry->mac, srcAddr, ETHER_ADDR_LEN) != 0) {
        sr_arpcache_insert(&sr->cache, srcAddr, src_ip);
    }
    free(existing_entry);
}
```

**Lección aprendida**: Los routers deben aprender direcciones MAC no solo de respuestas ARP, sino también de cualquier paquete IP recibido.

---

## 3. Problemas de Enrutamiento y Tabla de Rutas

### Problema 3.1: Rutas directamente conectadas no reconocidas
**Síntoma**: Router no podía responder a pings de hosts en redes directamente conectadas cuando la ruta no estaba explícitamente en la tabla de enrutamiento.

**Debugging utilizado**:
```c
printf("*** -> DEBUG: No route found in routing table for IP: ");
print_addr_ip_int(htonl(ipDst));
printf("\n*** -> DEBUG: Current routing table:\n");
print_routing_table(sr);
printf("*** -> DEBUG: Checking directly connected interfaces\n");
```

**Causa raíz**: La función `sr_send_icmp_error_packet` solo buscaba rutas en la tabla de enrutamiento (FIB), pero no verificaba si el destino estaba en una red directamente conectada.

**Solución**: Agregar verificación de interfaces directamente conectadas:
```c
if (!match) {
    /* Buscar en interfaces directamente conectadas */
    struct sr_if *if_walker = sr->if_list;
    while (if_walker) {
        uint32_t network = if_walker->ip & if_walker->mask;
        uint32_t dst_network = ipDst & if_walker->mask;
        if (network == dst_network) {
            iface = if_walker;
            break;
        }
        if_walker = if_walker->next;
    }
}
```

**Lección aprendida**: Siempre verificar redes directamente conectadas antes de descartar un paquete por falta de ruta.

---

## 4. Problemas de RIPv2

### Problema 4.1: Paquetes RIP no se procesaban
**Síntoma**: Los routers no aprendían rutas de otros routers a través de RIP, aunque recibían paquetes RIP.

**Debugging utilizado**:
```c
printf("*** -> DEBUG: RIP multicast packet received (224.0.0.9)\n");
printf("*** -> DEBUG: UDP port: %d (expected %d)\n", 
       udp_hdr->dst_port, RIP_PORT);
```

**Causa raíz**: Comparación incorrecta del puerto UDP sin conversión de byte order:
```c
// INCORRECTO:
if (udp_hdr->dst_port == RIP_PORT)

// CORRECTO:
if (ntohs(udp_hdr->dst_port) == RIP_PORT)
```

**Solución**: Usar `ntohs()` para convertir el puerto de network byte order a host byte order antes de comparar.

**Lección aprendida**: Todos los campos de headers de red están en network byte order y deben convertirse antes de usar en comparaciones o cálculos.

---

### Problema 4.2: Métricas RIP incorrectas
**Síntoma**: Las métricas de rutas aprendidas mostraban valores incorrectos (ej: 16777216 en lugar de 1).

**Debugging utilizado**:
```c
printf("*** -> RIP: Processing route entry: IP=");
print_addr_ip_int(htonl(rte_ip));
printf(", Metric=%u (raw: 0x%08x)\n", costo, rte->metric);
```

**Causa raíz**: El campo `metric` en los paquetes RIP está en network byte order, pero se estaba usando directamente sin conversión:
```c
// INCORRECTO:
uint32_t costo = rte->metric;

// CORRECTO:
uint32_t costo = ntohl(rte->metric);
```

**Solución**: Convertir la métrica de network byte order a host byte order usando `ntohl()`.

**Lección aprendida**: Todos los campos numéricos en protocolos de red están en network byte order (big-endian).

---

### Problema 4.3: Inicialización prematura de RIP
**Síntoma**: El thread de anuncios periódicos de RIP intentaba agregar rutas directamente conectadas antes de que las interfaces estuvieran configuradas, resultando en tablas de enrutamiento vacías.

**Debugging utilizado**:
```c
printf("*** -> RIP: DEBUG: Checking if_list, pointer: %p\n", (void*)sr->if_list);
printf("*** -> RIP: DEBUG: Waiting for interfaces (attempt %d/50)\n", wait_count);
printf("*** -> RIP: DEBUG: Interface %s not fully configured yet (IP=0x%08x, Mask=0x%08x)\n",
       int_temp->name, int_temp->ip, int_temp->mask);
```

**Causa raíz**: El thread de RIP se iniciaba inmediatamente al arrancar el router, pero las interfaces se configuran de forma asíncrona por el servidor VNS.

**Solución inicial**: Agregar espera con verificación:
```c
int wait_count = 0;
bool all_interfaces_ready = false;
while (wait_count < 50 && !all_interfaces_ready) {
    if (sr->if_list == NULL) {
        sleep(1);
        wait_count++;
        continue;
    }
    // Verificar que todas las interfaces tengan IP y máscara válidas
    // ...
}
```

**Solución final**: Usar `sleep(2)` simple, que es suficiente en la mayoría de los casos.

**Lección aprendida**: En sistemas con inicialización asíncrona, los threads deben esperar a que los recursos estén disponibles antes de usarlos.

---

### Problema 4.4: Conversión de Máscaras de Red
**Síntoma**: Las máscaras de red se mostraban incorrectamente (ej: "10.0.1.1" en lugar de "255.255.255.0") y los cálculos de red fallaban.

**Debugging utilizado**:
```c
printf("*** -> DEBUG: Interface %s: IP=0x%08x (", if_walker->name, if_ip_nbo);
print_addr_ip_int(htonl(if_ip_nbo));
printf("), Mask=0x%08x, Network=0x%08x (", if_mask_nbo, network);
print_addr_ip_int(htonl(network));
printf("), DstNetwork=0x%08x (", dst_network);
print_addr_ip_int(htonl(dst_network));
printf(")\n");
```

**Causa raíz**: Las máscaras pueden almacenarse en host byte order (little-endian, ej: `0x00ffffff` para /24) o network byte order (big-endian, ej: `0xffffff00` para /24), dependiendo del sistema.

**Solución**: Normalizar máscaras a network byte order antes de usar:
```c
uint32_t mask_raw = int_temp->mask;
if (mask_raw == 0x00ffffff) {
    mask.s_addr = inet_addr("255.255.255.0");
} else if (mask_raw == 0x0000ffff) {
    mask.s_addr = inet_addr("255.255.0.0");
} // ... etc
```

**Lección aprendida**: Las máscaras de red pueden tener problemas de byte order similares a las direcciones IP. Siempre normalizar antes de operaciones bitwise.

---

## 5. Herramientas y Técnicas de Debugging Utilizadas

### 5.1. Logs con Prefijos Específicos
Organizamos los logs con prefijos para facilitar el filtrado:

- `*** ->`: Logs generales del router
- `$$$ ->`: Logs de ARP
- `DEBUG ->`: Logs de debugging detallado
- `RIP:`: Logs específicos de RIP

**Ejemplo de uso**:
```bash
# Filtrar solo logs de RIP
./sr 2>&1 | grep "RIP:"

# Filtrar solo logs de debugging
./sr 2>&1 | grep "DEBUG"
```

### 5.2. Funciones de Impresión de Direcciones
**`print_addr_ip_int(uint32_t ip)`**: Convierte una IP de host byte order a string legible.

**Uso**:
```c
printf("IP: ");
print_addr_ip_int(htonl(ip_address));
printf("\n");
```

**`print_routing_table(struct sr_instance *sr)`**: Imprime toda la tabla de enrutamiento en formato legible.

**Uso**:
```c
printf("Current routing table:\n");
print_routing_table(sr);
```

### 5.3. Impresión Hexadecimal
Para debugging de byte order y valores raw:

```c
printf("Mask raw: 0x%08x\n", mask_raw);
printf("Mask NBO: 0x%08x\n", mask_nbo);
printf("IP: 0x%08x (", ip);
print_addr_ip_int(htonl(ip));
printf(")\n");
```

### 5.4. Verificación de Estructuras de Datos
```c
printf("*** -> DEBUG: if_list pointer: %p\n", (void*)sr->if_list);
printf("*** -> DEBUG: Interface count: %d\n", count);
printf("*** -> DEBUG: ARP entry exists: %s\n", existing_entry ? "yes" : "no");
```

### 5.5. Trazado de Flujo de Paquetes
```c
printf("*** -> Processing IP packet\n");
printf("*** -> IP packet: ");
print_addr_ip_int(htonl(src_ip));
printf(" -> ");
print_addr_ip_int(htonl(dest_ip));
printf("\n");
printf("*** -> Packet is for us\n");
printf("*** -> ICMP echo request received, sending echo reply\n");
```

### 5.6. Verificación de Estados de Threads
```c
printf("*** -> RIP: Periodic advertisement thread started\n");
printf("*** -> RIP: Waiting for interfaces to be configured...\n");
printf("*** -> RIP: All interfaces are now fully configured\n");
```

---

## 6. Estrategias de Debugging Efectivas

### 6.1. Debugging Incremental
- Empezar con casos simples (ping directo)
- Progresar a casos más complejos (multi-hop)
- Aislar problemas por capa (ARP → IP → RIP)

### 6.2. Comparación de Estados Esperados vs Reales
- Imprimir tabla de enrutamiento antes y después de operaciones
- Comparar valores hexadecimales con valores legibles
- Verificar conversiones de byte order explícitamente

### 6.3. Logs Condicionales
Usar macros `Debug()` que solo se activan en modo debug:
```c
#ifdef _DEBUG_
#define Debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define Debug(fmt, ...)
#endif
```

### 6.4. Verificación de Precondiciones
```c
if (!sr_iface) {
    fprintf(stderr, "Interface not found for ARP request\n");
    return;
}
```

---

## 7. Problemas Comunes y Soluciones Rápidas

| Problema | Síntoma | Solución Rápida |
|----------|---------|-----------------|
| Byte order incorrecto | Valores numéricos muy grandes | Usar `ntohs()`/`ntohl()` o `htons()`/`htonl()` |
| ARP cache vacía | Paquetes en cola ARP | Aprender MACs de paquetes IP recibidos |
| Ruta no encontrada | ICMP net unreachable | Verificar interfaces directamente conectadas |
| RIP no funciona | Tabla de rutas vacía | Verificar puerto UDP con `ntohs()` |
| Métricas incorrectas | Valores > 16 | Convertir métrica con `ntohl()` |
| Interfaces no configuradas | Tabla vacía al inicio | Agregar `sleep(2)` antes de agregar rutas |

---

## 8. Conclusiones

Los principales desafíos enfrentados fueron:

1. **Manejo de byte order**: Crítico en protocolos de red. Siempre convertir campos de headers.
2. **Sincronización de threads**: Los threads deben esperar a que los recursos estén listos.
3. **Aprendizaje proactivo**: Los routers deben aprender información de red de múltiples fuentes.
4. **Debugging sistemático**: Usar logs organizados y funciones de impresión especializadas facilita enormemente la depuración.

Las herramientas de debugging más útiles fueron:
- Logs con prefijos específicos para filtrado
- Funciones `print_addr_ip_int()` y `print_routing_table()`
- Impresión hexadecimal para debugging de byte order
- Trazado de flujo de paquetes paso a paso

---

## 9. Recomendaciones para Futuros Desarrollos

1. **Implementar logging estructurado desde el inicio**: Facilita el debugging posterior.
2. **Validar byte order sistemáticamente**: Crear funciones helper para conversión.
3. **Documentar asunciones de byte order**: Especialmente en estructuras de datos compartidas.
4. **Usar herramientas de análisis de paquetes**: Wireshark/tcpdump para verificar comportamiento real.
5. **Implementar tests unitarios**: Para validar conversiones de byte order y lógica de enrutamiento.

---

*Documento generado basado en la experiencia de desarrollo de la Parte 2 del proyecto de Redes.*


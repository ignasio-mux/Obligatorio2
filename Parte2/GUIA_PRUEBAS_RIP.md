# Guía de Pruebas - Parte 2: RIPv2

## Configuración Inicial

### 1. Compilar el Proyecto

```bash
cd Parte2/enrutamiento
make clean
make
```

**⚠️ Verificar que estás usando el ejecutable correcto:**

El script `run_sr.sh` usa la ruta relativa `./enrutamiento/sr`. Para asegurarte de que estás usando tu implementación de RIP:

**Desde tu máquina local (antes de ejecutar):**
```bash
# 1. Verificar que el ejecutable existe y es reciente
cd Parte2
ls -lh enrutamiento/sr

# 2. Verificar que tiene RIP compilado (debe mostrar referencias a RIP)
strings enrutamiento/sr | grep -i "rip" | head -3

# 3. Verificar que run_sr.sh apunta a enrutamiento/sr
cat run_sr.sh | grep "enrutamiento/sr"
# Debe mostrar: ./enrutamiento/sr -t 300 ...
```

**Desde la VM (mientras ejecutas los routers):**

Si quieres verificar desde la terminal donde ejecutas `./run_sr.sh`, puedes usar estos comandos:

**Ver el contenido de un archivo .sh:**

```bash
# 1. Ver el contenido completo del script (método más simple)
cat run_sr.sh

# 2. Ver con paginación (útil para archivos largos)
less run_sr.sh
# Presiona 'q' para salir, flechas para navegar

# 3. Ver con numeración de líneas
cat -n run_sr.sh

# 4. Ver solo las primeras líneas
head run_sr.sh
# O las primeras 10 líneas:
head -10 run_sr.sh

# 5. Ver solo las últimas líneas
tail run_sr.sh

# 6. Ver solo una línea específica (ej: línea 8)
sed -n '8p' run_sr.sh
# Debe mostrar: ./enrutamiento/sr -t 300 -v $2 -r rtable.$2 -s $1 -p 8888 -l $2.pcap

# 7. Buscar texto específico en el archivo
grep "enrutamiento" run_sr.sh
```

**Editar un archivo .sh (si necesitas modificarlo):**

```bash
# Opción 1: nano (editor simple, recomendado para principiantes)
nano run_sr.sh
# Guardar: Ctrl+O, Enter
# Salir: Ctrl+X

# Opción 2: vi/vim (editor más avanzado)
vi run_sr.sh
# Modo inserción: presiona 'i'
# Guardar y salir: :wq
# Salir sin guardar: :q!

# Opción 3: gedit (si tienes interfaz gráfica)
gedit run_sr.sh
```

**Otros comandos útiles para verificar:**

```bash
# 3. Verificar que el ejecutable existe y es accesible
ls -lh enrutamiento/sr
# Debe mostrar el ejecutable con permisos de ejecución

# 4. Verificar que el ejecutable tiene RIP compilado
strings enrutamiento/sr | grep -i "rip" | head -5
# Debe mostrar referencias a RIP como:
# -> RIP: Adding the directly connected network
# -> RIP: Printing the forwarding table
# etc.

# 5. Ver la ruta absoluta del ejecutable que se va a usar
readlink -f enrutamiento/sr
# O simplemente:
realpath enrutamiento/sr

# 6. Verificar el directorio actual (debe ser Parte2)
pwd
# Debe mostrar: .../Obligatorio2/Parte2
```

**Verificar mientras el router está corriendo:**

Si el router ya está ejecutándose, puedes verificar qué proceso está corriendo:

```bash
# Ver qué proceso 'sr' está corriendo
ps aux | grep "sr -t"

# Ver la ruta completa del ejecutable que está corriendo
ps aux | grep "sr -t" | grep -v grep | awk '{print $11}'

# O más detallado:
ps -ef | grep "enrutamiento/sr"
```

**Importante**: Ejecuta `./run_sr.sh` siempre desde el directorio `Parte2`, no desde otro lugar, para que la ruta relativa `./enrutamiento/sr` funcione correctamente.

### 2. Iniciar Mininet y POX

**Terminal 1 - Mininet:**
```bash
cd Parte2
sudo ./run_mininet.sh
```

**Terminal 2 - POX:**
```bash
cd Parte2
./run_pox.sh
```

**Terminal 3, 4, 5, 6, 7 - Routers:**
```bash
cd Parte2
# IP de la máquina donde corre Mininet/POX (servidor VNS)
# 
# Si ejecutas los routers desde la MISMA VM donde corre Mininet:
#   Usa: 127.0.0.1 (localhost)
#
# Si ejecutas los routers desde OTRA máquina (ej: tu Mac local):
#   1. En la VM, ejecuta: hostname -I
#   2. Usa la IP que muestre (ejemplo: 192.168.128.2)
#
# Ejemplo si ejecutas desde otra máquina:
./run_sr.sh 192.168.128.2 vhost1
./run_sr.sh 192.168.128.2 vhost2
./run_sr.sh 192.168.128.2 vhost3
./run_sr.sh 192.168.128.2 vhost4
./run_sr.sh 192.168.128.2 vhost5
#
# Ejemplo si ejecutas desde la misma VM:
# ./run_sr.sh 127.0.0.1 vhost1
# ./run_sr.sh 127.0.0.1 vhost2
# ... (etc)
```

**Esperar 30-60 segundos** después de iniciar todos los routers para que RIP converja.

---

## FASE 1: PRUEBAS BÁSICAS DE CONECTIVIDAD

### Prueba 1.1: Ping del Cliente al Primer Router (vhost1)

**Objetivo**: Verificar conectividad básica entre el cliente y su router de salida.

**Topología:**
```
client (100.0.0.1) ── vhost1-eth1 (100.0.0.50)
```

**Nota**: `100.0.0.50` es la IP de la interfaz `vhost1-eth1`, que es la interfaz del router vhost1 conectada directamente al cliente. Esta es la IP del gateway del cliente.

**Pasos:**
1. Iniciar todos los routers y esperar 30-60 segundos
2. En Mininet, ejecutar:

```bash
mininet> client ping -c 5 100.0.0.50
```

**Explicación**: Este ping verifica que el cliente puede comunicarse con su router de salida (gateway) directamente, sin necesidad de RIP. Es la prueba más básica de conectividad.

**Resultado esperado:**
```
PING 100.0.0.50 (100.0.0.50) 56(84) bytes of data.
64 bytes from 100.0.0.50: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from 100.0.0.50: icmp_seq=2 ttl=64 time=0.098 ms
64 bytes from 100.0.0.50: icmp_seq=3 ttl=64 time=0.105 ms
64 bytes from 100.0.0.50: icmp_seq=4 ttl=64 time=0.112 ms
64 bytes from 100.0.0.50: icmp_seq=5 ttl=64 time=0.099 ms

--- 100.0.0.50 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss
```

**Qué verificar:**
- ✅ 0% packet loss
- ✅ Tiempos de respuesta bajos (< 1ms típicamente)
- ✅ El router responde a ICMP Echo Request

**Si falla:**
- Verificar que vhost1 está corriendo
- Verificar configuración de IPs en `IP_CONFIG`
- Revisar logs de vhost1 para errores

---

### Prueba 1.2: Ping del Cliente a Otros Routers

**Objetivo**: Verificar que el cliente puede alcanzar routers más lejanos a través de la red.

**Routers a probar:**
- vhost2: `10.0.0.2` (1 salto desde vhost1)
- vhost3: `10.0.2.2` (1 salto desde vhost1)
- vhost4: `200.0.0.10` (2 saltos desde vhost1)
- vhost5: `200.100.0.15` (2 saltos desde vhost1)

**Pasos:**
```bash
# Router cercano (1 salto)
mininet> client ping -c 5 10.0.0.2

# Router cercano (1 salto)
mininet> client ping -c 5 10.0.2.2

# Router lejano (2 saltos)
mininet> client ping -c 5 200.0.0.10

# Router lejano (2 saltos)
mininet> client ping -c 5 200.100.0.15
```

**Resultado esperado:**
- ✅ Todos los pings deben tener 0% packet loss
- ✅ Tiempos de respuesta aumentan con el número de saltos
- ✅ Routers responden correctamente

**Qué verificar:**
- ✅ Las rutas RIP se aprendieron correctamente
- ✅ Los routers intermedios reenvían los paquetes
- ✅ No hay bucles de enrutamiento

**Si falla:**
- Verificar que RIP convergió (esperar más tiempo)
- Revisar tablas de enrutamiento en los logs de los routers
- Verificar que los routers intermedios tienen rutas correctas

---

### Prueba 1.3: Ping del Cliente a los Servidores

**Objetivo**: Verificar conectividad end-to-end hasta los servidores finales.

**Servidores:**
- server1: `150.150.0.2` (3 saltos desde client)
- server2: `100.100.0.2` (3 saltos desde client)

**Pasos:**
```bash
# Servidor 1
mininet> client ping -c 5 150.150.0.2

# Servidor 2
mininet> client ping -c 5 100.100.0.2
```

**Resultado esperado:**
```
PING 150.150.0.2 (150.150.0.2) 56(84) bytes of data.
64 bytes from 150.150.0.2: icmp_seq=1 ttl=62 time=0.456 ms
64 bytes from 150.150.0.2: icmp_seq=2 ttl=62 time=0.423 ms
64 bytes from 150.150.0.2: icmp_seq=3 ttl=62 time=0.441 ms
64 bytes from 150.150.0.2: icmp_seq=4 ttl=62 time=0.438 ms
64 bytes from 150.150.0.2: icmp_seq=5 ttl=62 time=0.445 ms

--- 150.150.0.2 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss
```

**Qué verificar:**
- ✅ 0% packet loss
- ✅ TTL disminuye correctamente (64 - número_de_saltos)
- ✅ Tiempos de respuesta razonables

**Si falla:**
- Verificar que todos los routers tienen rutas a los servidores
- Revisar logs de routers intermedios (vhost1, vhost2/vhost3, vhost4/vhost5)
- Verificar que los servidores tienen rutas de retorno al cliente

---

### Prueba 1.4: Traceroute del Cliente a los Servidores

**Objetivo**: Verificar la ruta completa que siguen los paquetes y confirmar que RIP eligió las rutas correctas.

**Pasos:**
```bash
# Traceroute a server1
mininet> client traceroute 150.150.0.2

# Traceroute a server2
mininet> client traceroute 100.100.0.2
```

**Resultado esperado para server1:**
```
traceroute to 150.150.0.2 (150.150.0.2), 30 hops max, 60 byte packets
 1  100.0.0.50 (100.0.0.50)  0.123 ms  0.098 ms  0.105 ms  # vhost1
 2  10.0.0.2 (10.0.0.2)  0.234 ms  0.198 ms  0.212 ms      # vhost2
 3  200.0.0.10 (200.0.0.10)  0.345 ms  0.312 ms  0.328 ms  # vhost4
 4  150.150.0.2 (150.150.0.2)  0.456 ms  0.423 ms  0.441 ms # server1
```

**Resultado esperado para server2:**
```
traceroute to 100.100.0.2 (100.100.0.2), 30 hops max, 60 byte packets
 1  100.0.0.50 (100.0.0.50)  0.123 ms  0.098 ms  0.105 ms  # vhost1
 2  10.0.2.2 (10.0.2.2)  0.234 ms  0.198 ms  0.212 ms      # vhost3
 3  200.100.0.15 (200.100.0.15)  0.345 ms  0.312 ms  0.328 ms # vhost5
 4  100.100.0.2 (100.100.0.2)  0.456 ms  0.423 ms  0.441 ms # server2
```

**Qué verificar:**
- ✅ La ruta sigue el camino esperado según la topología
- ✅ Cada salto muestra el router correcto
- ✅ No hay bucles (mismo router aparece múltiples veces)
- ✅ El número de saltos coincide con la métrica RIP

**Rutas esperadas según topología:**
```
client → vhost1 → vhost2 → vhost4 → server1
client → vhost1 → vhost3 → vhost5 → server2
```

**Si falla:**
- Verificar que RIP convergió completamente
- Revisar tablas de enrutamiento de cada router
- Verificar que no hay rutas incorrectas o bucles

---

### Prueba 1.5: Ping entre Routers

**Objetivo**: Verificar conectividad directa entre routers vecinos.

**Pasos:**
```bash
# Desde vhost1 a vhost2 (vecinos directos)
mininet> vhost1 ping -c 3 10.0.0.2

# Desde vhost1 a vhost3 (vecinos directos)
mininet> vhost1 ping -c 3 10.0.2.2

# Desde vhost2 a vhost4 (vecinos directos)
mininet> vhost2 ping -c 3 200.0.0.10

# Desde vhost3 a vhost5 (vecinos directos)
mininet> vhost3 ping -c 3 200.100.0.15
```

**Resultado esperado:**
- ✅ Todos los pings entre vecinos deben funcionar
- ✅ Tiempos muy bajos (< 0.5ms típicamente)

**Qué verificar:**
- ✅ Los routers pueden comunicarse directamente
- ✅ ARP funciona correctamente (Parte 1)
- ✅ Las interfaces están configuradas correctamente

---

## FASE 2: PRUEBAS AVANZADAS CON LA BIBLIOTECA

Una vez que las pruebas básicas de conectividad funcionan, puedes proceder con pruebas más detalladas del protocolo RIP.

---

## PRUEBAS POR FUNCIÓN IMPLEMENTADA

### 1. `sr_rip_send_requests()` - Requests Iniciales

#### Prueba 1.1: Verificar Envío de Requests al Iniciar

**Objetivo**: Confirmar que se envían REQUEST al iniciar cada router.

**Pasos:**
1. Detener todos los routers
2. Iniciar un router (ej: vhost1)
3. Esperar 2-3 segundos
4. Analizar los archivos .pcap generados automáticamente

**⚠️ Nota sobre xterm**: Si estás en una VM sin servidor X11, el comando `xterm vhost1` dará error "cannot connect to display". **No es necesario**: el script `run_sr.sh` ya genera archivos `.pcap` automáticamente (opción `-l $2.pcap`).

**Comandos (Método 1 - Usar archivos .pcap generados automáticamente):**
```bash
# Los archivos .pcap se generan automáticamente cuando ejecutas run_sr.sh
# Ejemplo: vhost1.pcap, vhost2.pcap, etc.

# Analizar el archivo .pcap desde tu máquina local o desde la VM:
tcpdump -r vhost1.pcap -n -v 'udp port 520' -c 10

# O usar Wireshark (más fácil, interfaz gráfica):
wireshark vhost1.pcap
```

**Comandos (Método 2 - Desde Mininet directamente, sin xterm):**
```bash
# En Mininet, ejecutar comando directamente en el host:
mininet> vhost1 tcpdump -i vhost1-eth1 -n -v 'udp port 520' -c 5

# O ejecutar en background y ver después:
mininet> vhost1 tcpdump -i vhost1-eth1 -n 'udp port 520' -w /tmp/rip_capture.pcap &
# ... esperar unos segundos ...
mininet> vhost1 tcpdump -r /tmp/rip_capture.pcap -n -v 'udp port 520'
```

**Comandos (Método 3 - Ver logs del router directamente):**
```bash
# Los logs del router muestran cuando envía paquetes RIP
# Buscar en la salida del router mensajes como:
# "RIP: Sending request packet on interface eth1"
```

**Qué verificar:**
- ✅ Se envía un REQUEST por cada interfaz del router
- ✅ Destino IP: `224.0.0.9` (multicast)
- ✅ Puerto UDP: `520`
- ✅ Command: `1` (REQUEST)
- ✅ Version: `2`
- ✅ Entrada especial: `family_identifier = 0`, `metric = 16`

**Salida esperada en logs del router:**
```
RIP: Sending request packet on interface eth1
RIP: Sending request packet on interface eth2
RIP: Sending request packet on interface eth3
```

#### Prueba 1.2: Verificar Respuesta a REQUEST

**Objetivo**: Confirmar que los routers responden a REQUEST.

**Pasos:**
1. Iniciar router A (vhost1)
2. Esperar que envíe REQUEST
3. Iniciar router B (vhost2, vecino)
4. Verificar que B responde

**Qué verificar:**
- ✅ Router B recibe REQUEST
- ✅ Router B envía RESPONSE inmediatamente
- ✅ RESPONSE contiene tabla de enrutamiento de B

**Salida esperada en logs:**
```
*** -> Solicitud RIP recibida
Respuesta RIP enviada
```

---

### 2. `sr_rip_periodic_advertisement()` - Anuncios Periódicos

#### Prueba 2.1: Verificar Anuncios Periódicos

**Objetivo**: Confirmar que se envían RESPONSE cada 10 segundos.

**Pasos:**
1. Iniciar todos los routers
2. Esperar estabilización (30-40 segundos)
3. Capturar tráfico durante 30 segundos

**Comandos:**
```bash
# Capturar tráfico RIP
tcpdump -i any -n 'udp port 520' -c 20 -w rip_periodic.pcap

# Analizar pcap
tcpdump -r rip_periodic.pcap -n 'udp port 520'
```

**Qué verificar:**
- ✅ Cada router envía RESPONSE cada ~10 segundos
- ✅ Destino: `224.0.0.9` (multicast)
- ✅ Command: `2` (RESPONSE)
- ✅ Contiene entradas de la tabla de enrutamiento

**Análisis temporal:**
```bash
# Extraer timestamps de paquetes RIP
tcpdump -r rip_periodic.pcap -n 'udp port 520' | awk '{print $1}' | \
  awk 'NR>1{print $1-prev} {prev=$1}'
# Debe mostrar intervalos de ~10 segundos
```

#### Prueba 2.2: Verificar Rutas Directamente Conectadas

**Objetivo**: Confirmar que las rutas directamente conectadas se agregan automáticamente.

**Pasos:**
1. Iniciar un router
2. Esperar 2-3 segundos (inicialización)
3. Verificar logs del router

**Qué verificar en logs:**
- ✅ Cada interfaz genera una ruta directamente conectada
- ✅ Gateway: `0.0.0.0`
- ✅ Métrica: Costo de interfaz (por defecto 1)
- ✅ `learned_from = 0` (no aprendida de vecino)
- ✅ `valid = 1` (siempre válida)

---

### 3. `sr_rip_send_response()` - Construcción de RESPONSE

#### Prueba 3.1: Verificar Formato de RESPONSE

**Objetivo**: Confirmar que los RESPONSE tienen formato correcto.

**Pasos:**
1. Iniciar routers
2. Capturar paquetes RIP
3. Analizar estructura

**Análisis con tcpdump:**
```bash
tcpdump -r vhost1.pcap -n -X 'udp port 520' | head -50
```

**Qué verificar:**
- ✅ Header RIP: command=2, version=2, zero=0
- ✅ Entradas RIP válidas (family=2, métricas 1-15)
- ✅ Máximo 25 entradas por mensaje
- ✅ Checksum UDP calculado correctamente
- ✅ TTL IP = 1

#### Prueba 3.2: Verificar Split Horizon con Poisoned Reverse

**Objetivo**: Confirmar que las rutas aprendidas se anuncian con métrica INFINITY por la misma interfaz.

**Escenario:**
```
Router A (vhost1) ──eth2── Router B (vhost2)
Router A aprende ruta a Red X desde Router B por eth2
```

**Pasos:**
1. Esperar que vhost1 aprenda rutas desde vhost2
2. Capturar RESPONSE de vhost1 por eth2
3. Verificar que las rutas aprendidas de vhost2 se anuncian con métrica 16

**Qué verificar:**
- ✅ Rutas aprendidas de vhost2 aparecen en RESPONSE de vhost1
- ✅ Pero con `metric = 16` (INFINITY) cuando se anuncian por eth2
- ✅ Otras rutas se anuncian con métrica normal

**Comando para analizar:**
```bash
# Filtrar solo RESPONSE de router A
tcpdump -r vhost1.pcap -n 'udp port 520 and ip src 10.0.0.1'
```

#### Prueba 3.3: Verificar Multicast vs Unicast

**Objetivo**: Confirmar uso correcto de multicast y unicast.

**Pasos:**
1. Capturar tráfico RIP
2. Analizar direcciones destino

**Qué verificar:**
- ✅ Anuncios periódicos: IP destino = `224.0.0.9`, MAC = `01:00:5E:00:00:09`
- ✅ Respuestas a REQUEST: Pueden ser unicast (IP específica)
- ✅ Triggered updates: IP destino = `224.0.0.9`

**Comando:**
```bash
tcpdump -r vhost1.pcap -n 'udp port 520' | grep -E '224.0.0.9|<IP_ESPECIFICA>'
```

---

### 4. `sr_handle_rip_packet()` - Procesamiento de Paquetes RIP

#### Prueba 4.1: Verificar Procesamiento de REQUEST

**Objetivo**: Confirmar que se responde correctamente a REQUEST.

**Pasos:**
1. Router A envía REQUEST
2. Router B recibe y procesa
3. Verificar respuesta

**Qué verificar:**
- ✅ Router B detecta REQUEST (command=1)
- ✅ Router B envía RESPONSE inmediatamente
- ✅ RESPONSE contiene tabla completa de B

**Logs esperados:**
```
*** -> Solicitud RIP recibida
Respuesta RIP enviada
```

#### Prueba 4.2: Verificar Procesamiento de RESPONSE

**Objetivo**: Confirmar que se procesan RESPONSE y se actualiza la tabla.

**Pasos:**
1. Iniciar Router A y Router B (vecinos)
2. Esperar que B envíe RESPONSE
3. Verificar que A actualiza su tabla

**Qué verificar:**
- ✅ Router A recibe RESPONSE de B
- ✅ Router A procesa cada entrada
- ✅ Router A actualiza tabla si encuentra mejor ruta
- ✅ Si hay cambios, se envía triggered update

**Logs esperados:**
```
*** -> Respuesta RIP recibida
La tabla de rutas fue modificada
Se envia un mensaje RIP a todos los nodos vecinos
La tabla de rutas es:
[tabla impresa]
```

#### Prueba 4.3: Verificar Validación de Paquetes

**Objetivo**: Confirmar que se rechazan paquetes inválidos.

**Qué verificar:**
- ✅ Paquete con versión incorrecta → rechazado
- ✅ Paquete con command inválido → rechazado
- ✅ Paquete con zero != 0 → rechazado
- ✅ Paquete con longitud incorrecta → rechazado

**Logs esperados:**
```
Paquete RIP no válido
```

---

### 5. `sr_rip_update_route()` - Actualización de Rutas

#### Prueba 5.1: Inserción de Nueva Ruta

**Objetivo**: Verificar que se insertan rutas nuevas correctamente.

**Escenario:**
```
Router A (vhost1) ── Router B (vhost2) ── Red X (vhost4)
Router A no conoce Red X inicialmente
```

**Pasos:**
1. Iniciar vhost2 y vhost4 primero
2. Esperar que vhost2 aprenda ruta a vhost4
3. Iniciar vhost1
4. Verificar que vhost1 aprende ruta a vhost4 vía vhost2

**Qué verificar en logs de vhost1:**
- ✅ Se inserta nueva ruta a Red X
- ✅ Gateway: IP de vhost2 (10.0.0.2)
- ✅ Métrica: Métrica de vhost2 + costo del enlace (normalmente 2)
- ✅ `learned_from`: IP de vhost2
- ✅ `valid = 1`
- ✅ `last_updated`: timestamp actual

#### Prueba 5.2: Actualización de Ruta Existente (Mismo Vecino)

**Objetivo**: Verificar actualización cuando el mismo vecino anuncia cambio.

**Pasos:**
1. vhost1 tiene ruta a Red X vía vhost2 (métrica 3)
2. vhost2 anuncia Red X con nueva métrica (2)
3. Verificar actualización

**Qué verificar:**
- ✅ vhost1 actualiza métrica a 3 (2 + 1)
- ✅ `last_updated` se refresca
- ✅ Gateway se mantiene (vhost2)

#### Prueba 5.3: Reemplazo por Mejor Ruta

**Objetivo**: Verificar que se reemplaza ruta si llega mejor métrica de otro origen.

**Escenario:**
```
vhost1 tiene: Red X vía vhost2 (métrica 5)
vhost3 anuncia: Red X (métrica 2)
```

**Pasos:**
1. vhost1 tiene ruta vía vhost2
2. vhost3 anuncia mejor ruta
3. Verificar reemplazo

**Qué verificar:**
- ✅ vhost1 reemplaza ruta
- ✅ Nuevo gateway: vhost3
- ✅ Nueva métrica: 3 (2 + 1)
- ✅ `learned_from`: IP de vhost3

#### Prueba 5.4: Ignorar Ruta Peor

**Objetivo**: Verificar que se ignoran rutas con peor métrica.

**Pasos:**
1. vhost1 tiene ruta vía vhost2 (métrica 3)
2. vhost3 anuncia ruta (métrica 5)
3. Verificar que no se actualiza

**Qué verificar:**
- ✅ Tabla de vhost1 no cambia
- ✅ Ruta sigue vía vhost2
- ✅ No se envía triggered update

#### Prueba 5.5: Manejo de Métrica Infinita

**Objetivo**: Verificar manejo correcto de métrica >= 16.

**Pasos:**
1. vhost1 tiene ruta vía vhost2
2. Desconectar vhost2 o hacer que anuncie métrica 16
3. Verificar marcado como inválida

**Qué verificar:**
- ✅ Si ruta existe y `learned_from == vhost2`: Marca `valid = 0`
- ✅ Pone `metric = 16`
- ✅ Inicia garbage collection
- ✅ Si ruta no existe: Ignora anuncio

---

### 6. `sr_rip_timeout_manager()` - Gestión de Timeouts

#### Prueba 6.1: Timeout de Ruta (60 segundos)

**Objetivo**: Verificar que las rutas expiran después de 60 segundos sin actualización.

**Escenario:**
```
Router A (vhost1) ── Router B (vhost2)
Router A aprende ruta desde B
Desconectar Router B
```

**Pasos:**
1. vhost1 aprende ruta desde vhost2
2. Detener proceso de vhost2 (o desconectar enlace)
3. Esperar 60+ segundos
4. Verificar timeout

**Qué verificar:**
- ✅ Después de 60 segundos sin actualización:
  - `valid = 0`
  - `metric = 16` (INFINITY)
  - `garbage_collection_time` se establece
- ✅ Se envía triggered update anunciando métrica INFINITY

**Logs esperados:**
```
RIP: Route timeout detected for 10.0.0.0/255.255.255.0
RIP: Timeout changes detected, sending triggered update
-> RIP: Printing the forwarding table after timeout
```

**Comando para acelerar prueba (modificar constantes temporalmente):**
```c
// En sr_rip.h, cambiar temporalmente para pruebas:
#define RIP_TIMEOUT_SEC 10  // En lugar de 60
```

#### Prueba 6.2: Refresco de Timestamp

**Objetivo**: Verificar que las rutas se refrescan cuando llegan actualizaciones.

**Pasos:**
1. vhost1 tiene ruta vía vhost2
2. Esperar 30 segundos
3. vhost2 envía actualización periódica
4. Verificar que `last_updated` se refresca

**Qué verificar:**
- ✅ `last_updated` se actualiza con cada RESPONSE
- ✅ Timeout se reinicia (60 segundos desde última actualización)

---

### 7. `sr_rip_garbage_collection_manager()` - Garbage Collection

#### Prueba 7.1: Eliminación de Rutas (100 segundos total)

**Objetivo**: Verificar que las rutas se eliminan después de 40 segundos en garbage collection.

**Pasos:**
1. vhost1 tiene ruta que expiró (valid=0, metric=16)
2. Esperar 40+ segundos adicionales (total 100 segundos desde última actualización)
3. Verificar eliminación

**Qué verificar:**
- ✅ Ruta se elimina de la tabla después de 40 segundos en garbage collection
- ✅ Se imprime tabla actualizada
- ✅ No se envía triggered update (ya se envió en timeout)

**Logs esperados:**
```
-> RIP: Garbage collection: Routes removed, printing routing table
```

**Tiempo total:**
- Timeout: 60 segundos → marca como inválida
- Garbage collection: 40 segundos adicionales → elimina
- **Total: 100 segundos** desde última actualización

#### Prueba 7.2: Rutas Directamente Conectadas NO se Eliminan

**Objetivo**: Confirmar que las rutas directamente conectadas nunca se eliminan.

**Qué verificar:**
- ✅ Rutas con `learned_from = 0` nunca expiran
- ✅ No se marcan como inválidas
- ✅ No entran en garbage collection

---

## PRUEBAS DE INTEGRACIÓN

### Prueba I.1: Convergencia Completa de la Red

**Objetivo**: Verificar que todos los routers aprenden todas las rutas.

**Topología:**
```
client ── vhost1 ── vhost2 ── vhost4 ── server1
              │        │
           vhost3 ── vhost5 ── server2
```

**Pasos:**
1. Iniciar todos los routers
2. Esperar 60-90 segundos (convergencia)
3. Verificar tablas de enrutamiento de cada router

**Qué verificar en cada router:**
- ✅ Rutas directamente conectadas presentes
- ✅ Rutas a todos los otros routers aprendidas
- ✅ Rutas a redes remotas aprendidas
- ✅ Métricas correctas (número de saltos)

**Comando para verificar conectividad:**
```bash
# En Mininet, desde client:
mininet> client ping -c 3 server1
mininet> client ping -c 3 server2

# Debe funcionar si las rutas están correctas
```

### Prueba I.2: Recuperación ante Fallo de Enlace

**Objetivo**: Verificar que la red converge después de un fallo.

**Pasos:**
1. Esperar convergencia inicial
2. Desconectar un enlace (ej: vhost1-vhost2)
3. Esperar 60-100 segundos
4. Verificar que se encuentran rutas alternativas

**Qué verificar:**
- ✅ Rutas vía enlace caído se marcan como inválidas
- ✅ Se encuentran rutas alternativas (si existen)
- ✅ Red converge a nueva topología

**Comando:**
```bash
# En Mininet, desconectar enlace:
mininet> link vhost1 vhost2 down

# Esperar y verificar que sigue habiendo conectividad
mininet> client ping -c 3 server1
```

### Prueba I.3: Split Horizon con Poisoned Reverse

**Objetivo**: Verificar que no hay bucles de enrutamiento.

**Escenario:**
```
Router A (vhost1) ── Router B (vhost2) ── Red X (vhost4)
```

**Pasos:**
1. vhost1 aprende Red X desde vhost2
2. Capturar RESPONSE de vhost1 hacia vhost2
3. Verificar que anuncia Red X con métrica 16

**Qué verificar:**
- ✅ vhost1 NO anuncia ruta aprendida de vhost2 con métrica normal
- ✅ Anuncia con métrica 16 (INFINITY) por la interfaz donde la aprendió
- ✅ Esto previene que vhost2 piense que puede llegar a X vía vhost1

### Prueba I.4: Triggered Updates

**Objetivo**: Verificar que los cambios generan actualizaciones inmediatas.

**Pasos:**
1. Red convergida
2. Desconectar un enlace
3. Capturar tráfico inmediatamente

**Qué verificar:**
- ✅ Cuando cambia la tabla, se envía RESPONSE inmediatamente
- ✅ No espera 10 segundos
- ✅ Se envía por todas las interfaces

**Análisis temporal:**
```bash
# Verificar que hay actualizaciones fuera del ciclo de 10 seg
tcpdump -r vhost1.pcap -n 'udp port 520' | \
  awk '{print $1}' | \
  awk 'NR>1{delta=$1-prev; if(delta<9) print "TRIGGERED:", delta} {prev=$1}'
```

---

## HERRAMIENTAS DE ANÁLISIS

**⚠️ Notas importantes:**

1. **Archivos .pcap automáticos**: El script `run_sr.sh` ya genera archivos `.pcap` automáticamente (vhost1.pcap, vhost2.pcap, etc.) con la opción `-l $2.pcap`. **No necesitas usar `xterm` o capturar manualmente**.

2. **Windows**: `tcpdump` no funciona en Windows. Usa:
   - **Wireshark** (interfaz gráfica) para analizar los archivos `.pcap`
   - **WinDump** (port de tcpdump para Windows) si necesitas línea de comandos
   - **WSL** (Windows Subsystem for Linux) si está disponible

3. **VM sin X11**: Si `xterm` da error "cannot connect to display", usa los archivos `.pcap` generados automáticamente o ejecuta comandos directamente desde Mininet sin `xterm`.

### 1. Análisis de Paquetes RIP con tcpdump (Linux/Mac)

**Nota**: Si estás en Windows, salta a la sección de Wireshark.

**Método recomendado: Usar archivos .pcap generados automáticamente**

Los archivos `.pcap` se generan automáticamente cuando ejecutas `run_sr.sh`:
- `vhost1.pcap`, `vhost2.pcap`, `vhost3.pcap`, etc.

```bash
# Analizar archivo .pcap de un router específico
tcpdump -r vhost1.pcap -n -v 'udp port 520'

# Ver estructura de paquetes (hexdump)
tcpdump -r vhost1.pcap -n -X 'udp port 520' | less

# Filtrar por router específico (IP de origen)
tcpdump -r vhost1.pcap -n 'udp port 520 and ip src 10.0.0.1'

# Ver intervalos entre paquetes (para verificar periodicidad)
tcpdump -r vhost1.pcap -n 'udp port 520' | \
  awk '{print $1}' | \
  awk 'NR>1{print $1-prev " segundos"} {prev=$1}'

# Contar cuántos paquetes RIP hay
tcpdump -r vhost1.pcap -n 'udp port 520' | wc -l
```

**Método alternativo: Capturar en tiempo real (si necesitas)**

```bash
# Desde Mininet directamente (sin xterm):
mininet> vhost1 tcpdump -i vhost1-eth1 -n -v 'udp port 520' -c 10

# O desde terminal de la VM:
sudo tcpdump -i any -n 'udp port 520' -w rip_capture.pcap
# ... esperar unos segundos ...
tcpdump -r rip_capture.pcap -n -v 'udp port 520'
```

### 2. Análisis con Wireshark (Funciona en Windows, Linux y Mac)

**Recomendado para Windows**: Wireshark es la mejor opción en Windows ya que `tcpdump` no está disponible.

```bash
# Abrir captura (desde terminal o desde el explorador de archivos)
wireshark vhost1.pcap

# O simplemente hacer doble clic en el archivo .pcap desde el explorador
# Wireshark se abrirá automáticamente
```

**Filtros útiles:**
- `udp.port == 520` - Solo RIP
- `rip.version == 2` - Solo RIPv2
- `rip.command == 1` - Solo REQUEST
- `rip.command == 2` - Solo RESPONSE
- `ip.dst == 224.0.0.9` - Solo multicast

**Análisis en Wireshark:**
- Ver estructura completa del paquete
- Verificar campos RIP
- Analizar métricas
- Verificar checksums

### 3. Monitoreo de Tablas de Enrutamiento

**Los logs del router muestran la tabla cuando:**
- Se inicializa RIP
- La tabla cambia
- Hay timeouts
- Hay garbage collection

**Buscar en logs:**
```bash
# Ver cambios en tabla
grep "tabla de rutas" vhost1.log

# Ver timeouts
grep "timeout" vhost1.log

# Ver garbage collection
grep "garbage" vhost1.log
```

---

## CHECKLIST DE VERIFICACIÓN

### Conectividad Básica (FASE 1)
- [ ] Ping del cliente al primer router funciona
- [ ] Ping del cliente a otros routers funciona
- [ ] Ping del cliente a los servidores funciona
- [ ] Traceroute muestra la ruta correcta
- [ ] No hay bucles en las rutas

### Funcionalidad Básica RIP
- [ ] Requests iniciales se envían al iniciar
- [ ] Responses se envían periódicamente cada ~10 seg
- [ ] Rutas directamente conectadas se agregan automáticamente
- [ ] Rutas se aprenden de vecinos
- [ ] Tabla de enrutamiento se actualiza correctamente

### Procesamiento de Mensajes
- [ ] REQUEST se procesa y genera RESPONSE
- [ ] RESPONSE se procesa y actualiza tabla
- [ ] Paquetes inválidos se rechazan
- [ ] Validación de formato funciona

### Actualización de Rutas
- [ ] Nuevas rutas se insertan
- [ ] Rutas existentes se actualizan si métrica mejora
- [ ] Rutas peores se ignoran
- [ ] Métrica infinita se maneja correctamente
- [ ] Rutas inválidas se reviven si llega actualización

### Timeouts y Garbage Collection
- [ ] Rutas expiran después de 60 segundos
- [ ] Rutas se eliminan después de 40 segundos adicionales
- [ ] Rutas directamente conectadas NO expiran
- [ ] Timestamps se refrescan con actualizaciones

### Split Horizon y Poisoned Reverse
- [ ] Rutas aprendidas se anuncian con métrica 16 por misma interfaz
- [ ] Otras rutas se anuncian con métrica normal
- [ ] No hay bucles de enrutamiento

### Triggered Updates
- [ ] Cambios en tabla generan actualización inmediata
- [ ] No espera ciclo de 10 segundos
- [ ] Se envía por todas las interfaces

### Formato de Paquetes
- [ ] TTL = 1 en todos los paquetes RIP
- [ ] Puerto UDP = 520
- [ ] IP destino multicast = 224.0.0.9
- [ ] MAC destino multicast = 01:00:5E:00:00:09
- [ ] Checksum UDP calculado correctamente
- [ ] Máximo 25 entradas por mensaje

### Convergencia
- [ ] Red converge a estado estable
- [ ] Todos los routers aprenden todas las rutas
- [ ] Métricas son correctas (número de saltos)
- [ ] Recuperación ante fallos funciona

---

## COMANDOS ÚTILES PARA DEBUGGING

### Ver logs en tiempo real
```bash
# Seguir logs de un router
tail -f vhost1.log | grep RIP

# Ver todos los mensajes RIP
tail -f vhost1.log | grep -E "RIP|rip"
```

### Capturar y analizar tráfico
```bash
# Capturar en tiempo real
sudo tcpdump -i any -n 'udp port 520' -v

# Guardar y analizar después
sudo tcpdump -i any -n 'udp port 520' -w rip.pcap
tcpdump -r rip.pcap -n -v 'udp port 520'
```

### Modificar constantes para pruebas rápidas
```c
// En sr_rip.h, temporalmente para pruebas:
#define RIP_ADVERT_INTERVAL_SEC 5   // En lugar de 10
#define RIP_TIMEOUT_SEC 20          // En lugar de 60
#define RIP_GARBAGE_COLLECTION_SEC 10 // En lugar de 40
```

**⚠️ IMPORTANTE**: Restaurar valores originales después de las pruebas.

---

## PROBLEMAS COMUNES Y SOLUCIONES

### Problema: Ping no funciona
**Verificar:**
- Todos los routers están corriendo
- RIP ha convergido (esperar 60-90 segundos)
- Tablas de enrutamiento tienen rutas correctas
- ARP funciona (Parte 1)

### Problema: No se envían anuncios periódicos
**Verificar:**
- Hilo `sr_rip_periodic_advertisement` se inició correctamente
- No hay errores en logs
- Mutex no está bloqueado indefinidamente

### Problema: Rutas no se aprenden
**Verificar:**
- Paquetes RIP llegan (tcpdump)
- Validación de paquetes pasa
- `sr_rip_update_route` se llama
- Métricas se calculan correctamente

### Problema: Timeouts no funcionan
**Verificar:**
- Hilo `sr_rip_timeout_manager` está corriendo
- `last_updated` se actualiza correctamente
- Cálculo de `difftime` es correcto

---

## CONCLUSIÓN

Esta guía sigue el enfoque recomendado:
1. **FASE 1**: Pruebas básicas de conectividad (ping y traceroute)
2. **FASE 2**: Pruebas avanzadas del protocolo RIP

Las funciones implementadas cubiertas:
- ✅ `sr_handle_rip_packet` - Procesamiento
- ✅ `sr_rip_update_route` - Actualización de rutas
- ✅ `sr_rip_send_response` - Construcción de RESPONSE
- ✅ `sr_rip_send_requests` - Requests iniciales
- ✅ `sr_rip_periodic_advertisement` - Anuncios periódicos
- ✅ `sr_rip_timeout_manager` - Gestión de timeouts
- ✅ `sr_rip_garbage_collection_manager` - Eliminación de rutas

Ejecuta estas pruebas sistemáticamente, empezando por las pruebas básicas de conectividad, para verificar que tu implementación funciona correctamente.

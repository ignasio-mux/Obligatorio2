# Errores Encontrados y Corregidos en la Implementación RIP

## Resumen de Problemas Corregidos

### 1. **Endianness de la métrica RIP** ✅ CORREGIDO
   - **Problema**: En `sr_rip_update_route`, la métrica `rte->metric` se leía directamente sin convertir de network byte order a host byte order.
   - **Corrección**: Agregado `ntohl(rte->metric)` para convertir correctamente la métrica.

### 2. **Protección con Mutex** ✅ CORREGIDO
   - **Problema**: `sr_rip_update_route` accedía a la tabla de enrutamiento sin protección con mutex, causando posibles condiciones de carrera.
   - **Corrección**: Agregado `pthread_mutex_lock(&rip_metadata_lock)` al inicio y `pthread_mutex_unlock()` en todos los puntos de salida.

### 3. **Revivir Rutas Inválidas** ✅ CORREGIDO
   - **Problema**: Cuando se revivía una ruta inválida, no se actualizaba `valid = 1` ni se reseteaba `garbage_collection_time = 0`.
   - **Corrección**: Agregado `entry_in_rt->valid = 1` y `entry_in_rt->garbage_collection_time = 0` al revivir rutas.

### 4. **garbage_collection_time en Rutas Nuevas** ✅ CORREGIDO
   - **Problema**: Al agregar nuevas rutas válidas, se usaba `now` como `garbage_collection_time` en lugar de `0`.
   - **Corrección**: Cambiado a `0` para rutas válidas (solo se usa cuando la ruta expira).

### 5. **Respuesta a RIP Request** ✅ CORREGIDO
   - **Problema**: Al responder a un RIP request, se usaba `dest_ip` (que puede ser multicast) en lugar de `orig_ip` (unicast).
   - **Corrección**: Cambiado a usar `orig_ip` para enviar la respuesta en unicast al router que hizo el request.

### 6. **Límite de Entradas RIP** ✅ CORREGIDO
   - **Problema**: El límite usaba `i <= 25` cuando debería ser `i < 25` (0-24 son 25 entradas).
   - **Corrección**: Corregido el cálculo de `num_entries` y el límite en el bucle.

### 7. **Uso de RIP_IP** ✅ CORREGIDO
   - **Problema**: En `sr_rip_periodic_advertisement` se usaba `htonl(RIP_IP)` cuando `RIP_IP` ya está en network byte order.
   - **Corrección**: Usar directamente `RIP_IP` sin conversión.

### 8. **Comparación de Multicast** ✅ CORREGIDO
   - **Problema**: La comparación de direcciones multicast usaba `htonl()` innecesariamente.
   - **Corrección**: Simplificada la comparación usando directamente los valores en network byte order.

### 9. **Actualización de Rutas** ✅ CORREGIDO
   - **Problema**: Al reemplazar una ruta con mejor métrica, se eliminaba y agregaba una nueva, lo cual era ineficiente y podía causar problemas de memoria.
   - **Corrección**: Actualizar la ruta existente directamente en lugar de eliminar y agregar.

### 10. **Llamada Duplicada a sr_rip_send_requests** ✅ CORREGIDO
   - **Problema**: En `sr_router.c` se llamaba `sr_rip_send_requests(sr)` directamente, pero esta función es un thread function y ya se llama desde `sr_rip_init`.
   - **Corrección**: Eliminada la llamada duplicada.

### 11. **Copia Segura de Nombre de Interfaz** ✅ CORREGIDO
   - **Problema**: Se usaba `memcpy()` para copiar el nombre de la interfaz sin asegurar terminación nula.
   - **Corrección**: Cambiado a `strncpy()` con terminación nula explícita.

## Problemas Potenciales Adicionales a Verificar

### 1. **Rutas Directamente Conectadas**
   - Las rutas directamente conectadas se agregan con `learned_from = htonl(0)` (0 en network byte order).
   - Esto está correcto, pero asegúrese de que `learned_from == 0` se use para identificar rutas directamente conectadas.

### 2. **Split Horizon con Poisoned Reverse**
   - La implementación verifica si `rt->interface` (interfaz de salida) coincide con `interface->name` (interfaz por la que se envía).
   - Esto es correcto: si la ruta se aprendió por la misma interfaz por la que se va a anunciar, se debe envenenar.

### 3. **Triggered Updates**
   - Las triggered updates se envían cuando hay cambios en la tabla.
   - Asegúrese de que se envíen después de desbloquear el mutex para evitar deadlocks.

### 4. **Validación de Paquetes RIP**
   - La función `sr_rip_validate_packet` valida el formato del paquete.
   - Asegúrese de que el cálculo de la longitud esperada sea correcto.

## Recomendaciones para Pruebas

1. **Pruebas de Convergencia**: Verificar que todos los routers converjan correctamente.
2. **Pruebas de Timeout**: Verificar que las rutas expiren correctamente después de 60 segundos.
3. **Pruebas de Garbage Collection**: Verificar que las rutas se eliminen después de 40 segundos en garbage collection.
4. **Pruebas de Split Horizon**: Verificar que las rutas no se anuncien de vuelta con métrica infinita cuando está habilitado.
5. **Pruebas de Triggered Updates**: Verificar que se envíen updates cuando hay cambios.
6. **Pruebas de Conteo a Infinito**: Seguir los pasos del instructivo para verificar el comportamiento con y sin split horizon.

## Notas Finales

- Todas las correcciones están implementadas y probadas sintácticamente.
- Se recomienda compilar y probar en el entorno Mininet.
- Verificar especialmente el manejo de endianness en diferentes arquitecturas.
- Asegurar que todos los mutex se liberen correctamente en todos los casos de error.



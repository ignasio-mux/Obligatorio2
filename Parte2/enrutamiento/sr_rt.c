/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr, const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32], gw[32], mask[32], iface[32];
    struct in_addr dest_addr, gw_addr, mask_addr;
    int cleared = 0;

    assert(filename);
    if (access(filename, R_OK) != 0) {
        perror("access");
        return -1;
    }

    fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    while (fgets(line, BUFSIZ, fp)) {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '#' || line[0] == '\0')
            continue;

        if (sscanf(line, "%31s %31s %31s %31s", dest, gw, mask, iface) != 4)
            continue;

        if (inet_aton(dest, &dest_addr) == 0) {
            fprintf(stderr, "Error loading RT: bad dest %s\n", dest);
            fclose(fp);
            return -1;
        }
        if (inet_aton(gw, &gw_addr) == 0) {
            fprintf(stderr, "Error loading RT: bad gw %s\n", gw);
            fclose(fp);
            return -1;
        }
        if (inet_aton(mask, &mask_addr) == 0) {
            fprintf(stderr, "Error loading RT: bad mask %s\n", mask);
            fclose(fp);
            return -1;
        }

        if (!cleared) {
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = NULL;
            cleared = 1;
        }

        struct sr_if* intf = sr_get_interface(sr, iface);
        uint8_t metric = 1;
        if (gw_addr.s_addr == htonl(0) && intf) {
            metric = intf->cost ? intf->cost : 1;
        }

        sr_add_rt_entry(sr,
                        dest_addr,
                        gw_addr,
                        mask_addr,
                        iface,
                        metric,
                        0,
                        htonl(0),
                        time(NULL),
                        1,
                        0);

        Debug("[SR-LOAD-RT] add dest=%s mask=%s gw=%s if=%s metric=%u",
              inet_ntoa(dest_addr), inet_ntoa(mask_addr),
              inet_ntoa(gw_addr), iface, metric);
    }

    fclose(fp);
    return 0;
}

struct sr_rt *sr_find_lpm_entry(struct sr_instance *sr, uint32_t ip_addr) {
    /* Busco la mejor ruta para una IP usando Longest Prefix Match */
    struct sr_rt *rt = sr->routing_table;
    struct sr_rt *match = NULL;
    uint32_t max_mask = 0;
    while (rt) {
        if ((rt->dest.s_addr & rt->mask.s_addr) == (ip_addr & rt->mask.s_addr)) {
            uint32_t mask_val = ntohl(rt->mask.s_addr);
            if (mask_val > max_mask) {
                max_mask = mask_val;
                match = rt;
            }
        }
        rt = rt->next;
    }
    return match;
}

struct sr_rt* sr_find_learned_route (struct sr_rt* head, uint32_t dest_ip, uint32_t dest_mask){
    bool find = false;
    while (head != NULL && !find) {
        if(head->dest.s_addr == dest_ip && head->mask.s_addr == dest_mask) 
            find = true; 
        else 
            head = head->next;     
    }

    return head;
}

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_add_rt_entry(struct sr_instance* sr,
                     struct in_addr dest,            /* destino */
                     struct in_addr gw,              /* next-hop */
                     struct in_addr mask,            /* máscara */
                     const char* if_name,            /* nombre de interfaz */
                     uint8_t metric,                 /* métrica RIP */
                     uint16_t route_tag,             /* etiqueta de ruta */
                     uint32_t learned_from,          /* IP vecino origen (network order) */
                     time_t last_updated,            /* timestamp última actualización */
                     uint8_t expired,                  /* ruta válida */
                     time_t garbage_collection_time)                /* cambió recientemente */
{
    struct sr_rt* rt_walker = 0;

    /* Requisitos básicos */
    assert(sr);
    assert(if_name);

    /* Caso de lista vacía: crear cabeza */
    if (sr->routing_table == NULL) {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);

        sr->routing_table->next = NULL;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;

        /* Copiar nombre de interfaz asegurando terminación nula */
        strncpy(sr->routing_table->interface, if_name, sr_IFACE_NAMELEN - 1);
        sr->routing_table->interface[sr_IFACE_NAMELEN - 1] = '\0';

        /* Campos de la Parte 2 */
        sr->routing_table->metric       = metric;
        sr->routing_table->route_tag    = route_tag;
        sr->routing_table->learned_from = learned_from;
        sr->routing_table->last_updated = last_updated;
        sr->routing_table->valid        = expired;
        sr->routing_table->garbage_collection_time      = garbage_collection_time;

        return;
    }

    /* Buscar el último nodo */
    rt_walker = sr->routing_table;
    while (rt_walker->next != NULL) {
        rt_walker = rt_walker->next;
    }

    /* Crear y encadenar nuevo nodo al final */
    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);

    rt_walker = rt_walker->next;
    rt_walker->next = NULL;

    /* Campos base */
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;

    /* Copiar nombre de interfaz asegurando terminación nula */
    strncpy(rt_walker->interface, if_name, sr_IFACE_NAMELEN - 1);
    rt_walker->interface[sr_IFACE_NAMELEN - 1] = '\0';

    /* Campos de la Parte 2 */
    rt_walker->metric       = metric;
    rt_walker->route_tag    = route_tag;
    rt_walker->learned_from = learned_from;
    rt_walker->last_updated = last_updated;
    rt_walker->valid        = expired;
    rt_walker->garbage_collection_time      = garbage_collection_time;
}

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\tGateway\t\tMask\tIface\n");

    rt_walker = sr->routing_table;
    
    sr_print_routing_entry(rt_walker);
    while(rt_walker->next)
    {
        rt_walker = rt_walker->next; 
        sr_print_routing_entry(rt_walker);
    }

} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("%s\t\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\n",entry->interface);

} /* -- sr_print_routing_entry -- */


/* Delete route entry */
void sr_del_rt_entry(struct sr_rt** head, struct sr_rt* victim) {
    if (!head || !*head || !victim) return;

    if (*head == victim) {
        struct sr_rt* next = victim->next;
        free(victim);
        *head = next;
        return;
    }

    struct sr_rt* prev = *head;
    while (prev && prev->next && prev->next != victim) {
        prev = prev->next;
    }

    if (prev && prev->next == victim) {
        prev->next = victim->next;
        free(victim);
    }
}
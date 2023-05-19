<h1 align="center">Внедрение сигнатуры в nDPI</h1>

1. Переходим в файл `src/include/ndpi_protocol_ids.h` и добавляем запись о протоколе `Neo4j` с уникальным ID:
```c++
NDPI_PROTOCOL_NEO4J                 = 305, /* Neo4j*/ 
```

2. В папке `src/lib/protocols/` создаём файл `neo4j.c`, куда записываем сигнатуру для обнаружения протокола `Neo4j`:

```c++
/*
* neo4j.c
*/

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NEO4J

#include "ndpi_api.h"


static void ndpi_int_neo4j_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
                                          struct ndpi_flow_struct *flow)
{

    NDPI_LOG_INFO(ndpi_struct, "found Neo4j\n");

    ndpi_set_detected_protocol(ndpi_struct,
                               flow,
                               NDPI_PROTOCOL_NEO4J,
                               NDPI_PROTOCOL_UNKNOWN,
                               NDPI_CONFIDENCE_DPI);
}

void ndpi_search_neo4j(struct ndpi_detection_module_struct *ndpi_struct, 
                       struct ndpi_flow_struct *flow)
{

    NDPI_LOG_DBG(ndpi_struct, "search Neo4j\n");
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;
    
    if(packet->tcp && packet->payload){

        if(ntohs(packet->tcp->source) == 7687 && packet->payload_packet_len >= 9 && packet->payload[0] == 0x82){
            ndpi_int_neo4j_add_connection(ndpi_struct, flow);
        }
       
        if(ntohs(packet->tcp->dest) == 7687 && packet->payload_packet_len >= 12 && packet->payload[0] == 0x82){
            ndpi_int_neo4j_add_connection(ndpi_struct, flow);
        }

    }
}

void init_neo4j_dissector(struct ndpi_detection_module_struct *ndpi_struct, 
                          u_int32_t *id, 
                          NDPI_PROTOCOL_BITMASK *detection_bitmask)
{

    ndpi_set_bitmask_protocol_detection("Neo4j", 
                                        ndpi_struct, 
                                        detection_bitmask, 
                                        *id, 
                                        NDPI_PROTOCOL_NEO4J, 
                                        ndpi_search_neo4j, 
                                        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, 
                                        SAVE_DETECTION_BITMASK_AS_UNKNOWN, 
                                        ADD_TO_DETECTION_BITMASK);
    *id += 1;
}
```
3. Переходим в файл `src/include/ndpi_protocols.h` и добавляем наш диссектор(анализатор):

```c++
void init_neo4j_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask);
```

4. Переходим в файл `src/lib/ndpi_main.c`: 
* Находим функцию `ndpi_callback_init` и добавляем наш диссектор(анализатор):
```c++
/* Neo4j */
init_neo4j_dissector(ndpi_str, &a, detection_bitmask);
```
* Находим функцию `ndpi_init_protocol_defaults` и инициализируем значения по умолчанию для нашего протокола `Neo4j`:
```c++
ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NEO4J,
            "Neo4j", NDPI_PROTOCOL_CATEGORY_DATABASE,
            ndpi_build_default_ports(ports_a, 7687, 0, 0, 0, 0) /* TCP */,
            ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
```
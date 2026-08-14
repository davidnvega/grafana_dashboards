# Runbook: respuesta a reportes de abuso con Akvorado + FastNetMon

Procedimiento para investigar y responder un reporte de abuso recibido del upstream
(Cogent / ISP Abuse Department) usando los datos de flujo que ya tenemos en Akvorado,
y las acciones correctivas asociadas.

Caso de referencia: **Ticket 12172485 — "Unauthorized Access Attempt" — IP 38.3.130.200**.

---

## 0. Lectura del reporte

Lo que el correo sí dice:

| Campo | Valor |
|---|---|
| Ticket | 12172485 |
| Categoría | Unauthorized Access Attempt |
| IP señalada | 38.3.130.200 |
| Dirección implícita | **saliente** — la IP bajo nuestro control es el *origen* del intento |
| Portal | `https://abuse.sys.cogentco.com/ash/collect/12172485/<token>` |
| Acción esperada | investigar, remediar y **responder por el portal** |

Lo que el correo **no** dice, y sin lo cual no se puede consultar Akvorado:

- **Timestamp del evento y zona horaria** (crítico: define la ventana de búsqueda).
- **IP(s) destino** de los intentos.
- **Puerto / protocolo** (SSH 22, RDP 3389, Telnet 23, SMB 445, VNC 5900, SIP 5060…).
- **Reporter original** (SANS/DShield, AbuseIPDB, un honeypot, otro ISP…).
- **Volumen** (nº de intentos, si fue escaneo masivo o dirigido).

> **Paso 1, obligatorio y bloqueante:** abrir la URL del portal y extraer esos campos.
> Cogent reenvía reportes de terceros y normalmente adjunta el log crudo (líneas de
> `sshd`, firewall o IDS con fecha, IP destino y puerto). Todo lo demás depende de esto.

### Contexto de direccionamiento

`38.0.0.0/8` es el bloque histórico PSINet/Cogent (AS174). Que Cogent nos reporte
`38.3.130.200` es coherente con una IP asignada por Cogent a nuestra red.

**Verificar antes de continuar** (no se pudo hacer desde este entorno, egress bloqueado):

```bash
whois 38.3.130.200                       # o: curl -s https://rdap.arin.net/registry/ip/38.3.130.200
```

Confirmar que el rango figura como asignación nuestra (SWIP/reassign) y que la IP
está realmente en uso interno. Si el rango **no** es nuestro, es un reporte mal
dirigido y la respuesta al portal es exactamente eso, con la evidencia de RDAP.

### Plazos y riesgo

Los reportes de abuso de Cogent esperan respuesta típicamente en **24–72 h**. Ignorar
o no responder puede escalar a null-route de la IP o suspensión del servicio según su
AUP. Aun si concluimos que es un falso positivo, **hay que responder** — la opción
"ignore" del portal deja registro pero no cierra el ticket a nuestro favor.

---

## 1. Investigación en Akvorado

### 1.1 Antes de consultar: qué puede y qué no puede ver Akvorado

Tres límites que condicionan la interpretación del resultado:

1. **Retención de la tabla cruda.** Sólo la tabla `flows` (resolución 0) guarda
   `SrcAddr`/`DstAddr`/`SrcPort`/`DstPort`. Su TTL por defecto es **15 días**. Las
   tablas agregadas (`flows_1m0s`, `flows_5m0s`, `flows_1h0m0s`) **no** conservan
   direcciones ni puertos, así que si el evento es más antiguo que el TTL crudo,
   Akvorado ya no puede responder quién habló con quién. Verificar el TTL real:

   ```sql
   SELECT name, engine_full FROM system.tables WHERE database = currentDatabase() AND name LIKE 'flows%';
   SELECT min(TimeReceived), max(TimeReceived) FROM flows;
   ```

2. **Muestreo (sampling).** Un ataque de fuerza bruta o un escaneo es de **bajo
   volumen**: paquetes pequeños, pocos bytes por flujo. Con un sampling de 1:1000 o
   1:10000 en el router, **es perfectamente posible que Akvorado no haya capturado
   ni un solo flujo del incidente**. Ausencia de evidencia ≠ evidencia de ausencia:
   nunca responder al ISP "no encontramos nada en netflow, por tanto no ocurrió".

3. **Visibilidad de la exportación.** Sólo se ve tráfico que atraviesa un router que
   exporta flujos, y el sentido correcto (`InIfBoundary` / `OutIfBoundary`). Si el
   host comprometido sale por una ruta sin exportador, no aparece.

### 1.2 Consultas en la consola web (lenguaje de filtro Akvorado)

Operadores disponibles: `=`, `!=`, `<`, `<=`, `>`, `>=`, `IN`, `NOTIN`, `LIKE`,
`UNLIKE`, `ILIKE`, `IUNLIKE`. `Ctrl-Space` autocompleta, `Ctrl-Enter` ejecuta.

> Nota de rendimiento: filtrar por `SrcAddr`/`DstAddr`/`SrcPort`/`DstPort` obliga a
> usar la tabla cruda, así que estas consultas son lentas. Acotar bien el rango de
> tiempo.

**a) Todo el tráfico saliente de la IP reportada** — poner el rango de tiempo en
±2 h alrededor del timestamp del reporte:

```
SrcAddr = 38.3.130.200
```

Dimensiones: `DstAddr`, `DstPort`, `Proto`. Tipo: *Stacked areas*, "Top by" = `max`.

**b) Confirmar el patrón del abuso** — si el portal indica, por ejemplo, SSH:

```
SrcAddr = 38.3.130.200 AND DstPort = 22 AND Proto = TCP
```

**c) Escaneo / fuerza bruta genérica sobre puertos de administración:**

```
SrcAddr = 38.3.130.200
  AND Proto = TCP
  AND DstPort IN (22, 23, 445, 1433, 3306, 3389, 5432, 5900, 8080)
```

**d) ¿Es el único host afectado?** Quitar la IP y buscar el mismo patrón en toda la
red — si hay más hosts escaneando, el problema es sistémico (malware lateral, red
comprometida) y no un incidente aislado:

```
DstPort = 22 AND Proto = TCP AND InIfBoundary = internal
```

Dimensión `SrcAddr`, límite 20, "Top by" = `max`.

**e) Sankey de dispersión** — dimensiones `SrcAddr` → `DstCountry` → `DstPort`, filtro
`SrcAddr = 38.3.130.200`. Un abanico ancho hacia muchos países y un solo puerto es la
firma visual clásica de un escáner.

**f) ¿Entró antes de salir?** Buscar el compromiso inicial invirtiendo el sentido:

```
DstAddr = 38.3.130.200
```

Dimensiones `SrcAddr`, `DstPort`. Interesa la ventana de días **anteriores** al evento.

### 1.3 Consultas SQL directas a ClickHouse

Más rápidas y precisas que la consola para trabajo forense. Sustituir la ventana de
tiempo por la del reporte (Akvorado guarda `TimeReceived` en **UTC**).

```console
docker compose exec clickhouse clickhouse-client
```

Recordatorio de esquema: Akvorado guarda las IPs internamente como IPv6 (usar
`toIPv6('38.3.130.200')`), y `Bytes`/`Packets` son valores **crudos** — hay que
multiplicarlos por `SamplingRate` para obtener volúmenes reales.

**Perfil completo del evento — a quién, por qué puerto, cuánto:**

```sql
SELECT
    DstAddr,
    DstPort,
    dictGetOrDefault('protocols', 'name', Proto, toString(Proto)) AS proto,
    count()                              AS flows_muestreados,
    sum(Packets * SamplingRate)          AS paquetes_est,
    sum(Bytes   * SamplingRate)          AS bytes_est,
    min(TimeReceived)                    AS primero,
    max(TimeReceived)                    AS ultimo
FROM flows
WHERE TimeReceived BETWEEN toDateTime('2026-08-13 00:00:00', 'UTC')
                       AND toDateTime('2026-08-14 00:00:00', 'UTC')
  AND SrcAddr = toIPv6('38.3.130.200')
GROUP BY DstAddr, DstPort, proto
ORDER BY flows_muestreados DESC
LIMIT 100;
```

**Firma de escaneo: abanico de destinos por minuto.** Muchos `DstAddr` distintos con
muy pocos bytes por flujo = escaneo, no tráfico legítimo:

```sql
SELECT
    toStartOfMinute(TimeReceived)        AS minuto,
    uniqExact(DstAddr)                   AS destinos_distintos,
    uniqExact(DstPort)                   AS puertos_distintos,
    count()                              AS flows,
    round(avg(Bytes / Packets), 1)       AS bytes_por_paquete
FROM flows
WHERE TimeReceived BETWEEN toDateTime('2026-08-13 00:00:00', 'UTC')
                       AND toDateTime('2026-08-14 00:00:00', 'UTC')
  AND SrcAddr = toIPv6('38.3.130.200')
GROUP BY minuto
ORDER BY destinos_distintos DESC
LIMIT 50;
```

**Localizar el host y la ruta** — por dónde entró/salió el tráfico, para saber a qué
switch/interfaz/cliente corresponde:

```sql
SELECT
    ExporterAddress,
    ExporterName,
    InIfName,
    InIfDescription,
    OutIfName,
    count() AS flows
FROM flows
WHERE TimeReceived BETWEEN toDateTime('2026-08-13 00:00:00', 'UTC')
                       AND toDateTime('2026-08-14 00:00:00', 'UTC')
  AND SrcAddr = toIPv6('38.3.130.200')
GROUP BY ExporterAddress, ExporterName, InIfName, InIfDescription, OutIfName
ORDER BY flows DESC;
```

**Barrido de toda la red: ¿hay más escáneres?** Ejecutar aunque la IP reportada salga
limpia — si la IP es una salida NAT, el atacante real es otro host interno:

```sql
SELECT
    SrcAddr,
    uniqExact(DstAddr) AS destinos,
    uniqExact(DstPort) AS puertos,
    count()            AS flows
FROM flows
WHERE TimeReceived >= now() - INTERVAL 24 HOUR
  AND Proto = 6
  AND DstPort IN (22, 23, 445, 1433, 3389, 5900)
GROUP BY SrcAddr
HAVING destinos > 100
ORDER BY destinos DESC
LIMIT 50;
```

**Si `TCPFlags` está habilitado** (columna deshabilitada por defecto en Akvorado):
flujos con sólo SYN y sin respuesta son la confirmación definitiva de escaneo. Para
activarla, añadirla a `schema.enabled` en la configuración del orquestador — sólo
afecta a flujos futuros, no reconstruye el pasado.

### 1.4 Identificar al cliente detrás de un NAT/CGNAT

La pregunta operativa real: si `38.3.130.200` es una IP de salida compartida, ¿puede
Akvorado decirnos qué abonado estaba detrás en ese instante?

**Depende de una sola cosa, comprobable de inmediato:**

```sql
SELECT name, type FROM system.columns
WHERE table = 'flows' AND name LIKE '%NAT%';
```

**Si devuelve filas** → Akvorado puede desenmascarar al cliente directamente. Las
columnas `SrcAddrNAT` / `SrcPortNAT` se rellenan desde los campos IPFIX
`postNATSourceIPv4Address` / `postNAPTSourceTransportPort`, así que la semántica es:

- `SrcAddr` / `SrcPort` → dirección y puerto **privados**, el abonado real
- `SrcAddrNAT` / `SrcPortNAT` → dirección y puerto **públicos** tras la traducción

La consulta de desenmascarado, buscando por la IP pública reportada:

```sql
SELECT
    TimeReceived,
    SrcAddr    AS abonado_privado,
    SrcPort    AS puerto_privado,
    SrcAddrNAT AS ip_publica,
    SrcPortNAT AS puerto_publico,
    DstAddr,
    DstPort
FROM flows
WHERE TimeReceived BETWEEN toDateTime('2026-08-13 00:00:00', 'UTC')
                       AND toDateTime('2026-08-14 00:00:00', 'UTC')
  AND SrcAddrNAT = toIPv6('38.3.130.200')
  -- AND SrcPortNAT = <puerto de origen del reporte>   <-- descomentar: identificación exacta
  -- AND DstAddr   = toIPv6('<destino del reporte>')
ORDER BY TimeReceived
LIMIT 200;
```

Sin el `SrcPortNAT` del reporte, la consulta devuelve **todos** los abonados que
compartían esa IP pública en la ventana — sirve para acotar, no para acusar.

**Si no devuelve filas** → Akvorado no puede responder a esta pregunta para este
incidente, y no hay forma de arreglarlo a posteriori. Las columnas NAT vienen
**deshabilitadas por defecto**, sólo existen en la tabla cruda (`main-table-only`), y
habilitarlas (añadir `SrcAddrNAT`, `SrcPortNAT`, `DstAddrNAT`, `DstPortNAT` a
`schema.enabled`) afecta únicamente a flujos futuros. Además el CGNAT tiene que estar
exportando IPFIX con esos campos: NetFlow v5/v9 clásico y sFlow no los llevan.

En ese caso la única fuente es el **log de traducción del CGNAT/firewall**, y la clave
de búsqueda es el cuarteto:

> IP pública + **puerto de origen público** + timestamp exacto (con zona horaria) + destino

**El puerto de origen es el dato imprescindible.** Sin él la identificación de un
abonado tras CGNAT es imposible salvo que sólo uno hablara con ese destino en ese
segundo. Y ese puerto normalmente **sí viene en el reporte de abuso** — es otra razón
por la que abrir el portal es el paso bloqueante.

Akvorado sigue aportando aquí aunque no tenga las columnas NAT: la tabla cruda guarda
`SrcPort`, así que puede confirmar qué puertos públicos estuvieron activos hacia ese
destino en la ventana, y con eso se acota la búsqueda en el log del CGNAT.

### 1.4.1 Si la IP es una asignación estática, no NAT

Entonces Akvorado puede identificar al cliente por sí solo, si el enriquecimiento está
poblado. Dos vías, ambas consultables en la misma fila del flujo:

```sql
SELECT
    SrcAddr,
    SrcNetName, SrcNetRole, SrcNetSite, SrcNetTenant,
    ExporterName, InIfName, InIfDescription,
    count() AS flows
FROM flows
WHERE TimeReceived BETWEEN toDateTime('2026-08-13 00:00:00', 'UTC')
                       AND toDateTime('2026-08-14 00:00:00', 'UTC')
  AND SrcAddr = toIPv6('38.3.130.200')
GROUP BY ALL;
```

- **`SrcNetName` / `SrcNetRole` / `SrcNetSite` / `SrcNetTenant`** — atributos que
  Akvorado asigna por prefijo. Se definen estáticamente en `networks`, o se importan
  con `network-sources`, que descarga un JSON por HTTP y lo transforma con una
  expresión `jq`. **Esto es lo que más rentabiliza de cara al próximo reporte**: si se
  conecta el IPAM a `network-sources`, cada flujo llega ya etiquetado con el cliente y
  la identificación pasa de horas de correlación a una columna en la consulta.
- **`InIfDescription`** — la descripción de la interfaz vía SNMP, habilitada por
  defecto. En muchos operadores lleva el circuit ID o el nombre del cliente, así que a
  menudo resuelve la pregunta sin configurar nada más.

### 1.4.2 La limitación que ninguna columna arregla

Para desenmascarar hace falta **el flujo concreto** del incidente, no una estimación
agregada. Con un muestreo de 1:1000 o 1:10000, la probabilidad de haber capturado
justo los paquetes del intento de acceso es baja. Las columnas NAT no cambian eso: si
el flujo no se muestreó, no existe en la base.

Conclusión práctica: para atribuir a un abonado tras CGNAT, **Akvorado es una fuente
secundaria**. La primaria es el log de traducción del CGNAT, que registra todas las
sesiones sin muestrear. Akvorado corrobora, acota la ventana y aporta contexto de
patrón; el log del CGNAT es el que identifica.

### 1.5 Cruce con FastNetMon

FastNetMon ya está desplegado (es la fuente de los dashboards de este repo). Revisar:

- Alertas y baneos en la ventana del incidente (`fastnetmon_client`, `/var/log/fastnetmon.log`,
  o la tabla de ClickHouse si se usa el backend avanzado).
- Los dashboards **Top hosts** / **Top outgoing** de este repositorio, filtrando por
  `38.3.130.200` en la ventana correspondiente.
- Si FastNetMon no disparó nada, es esperable: sus umbrales por defecto están pensados
  para DDoS volumétrico, no para escaneo de bajo caudal. Ver §2.3.

---

## 2. Acciones correctivas

Ordenadas por urgencia. Las de contención se ejecutan aunque la investigación siga abierta.

### 2.1 Contención inmediata (mismo día)

1. **Identificar y aislar el host.** Del resultado de §1.3 se obtiene exportador +
   interfaz; con eso, el puerto de switch, la VM o el cliente. Si es un servidor
   propio: sacarlo de producción o ponerlo en VLAN de cuarentena. Si es de cliente:
   notificar y aplicar filtro.
2. **Bloquear el patrón de abuso en el borde**, mientras se limpia el host:

   ```
   ! Ejemplo conceptual — ACL de salida sobre el host implicado
   deny tcp host 38.3.130.200 any eq 22
   deny tcp host 38.3.130.200 any eq 23
   deny tcp host 38.3.130.200 any eq 3389
   deny tcp host 38.3.130.200 any eq 445
   permit ip any any
   ```

   Alternativa más quirúrgica si hay FlowSpec disponible: anuncio temporal que descarte
   `src 38.3.130.200/32, proto tcp, dport 22` en lugar de tocar ACLs a mano.
3. **Preservar evidencia antes de reinstalar**: `/var/log/auth.log`, `last`, `crontab -l`
   de todos los usuarios, `ss -tunap`, procesos, y una copia del disco si es viable.
   Reinstalar destruye la evidencia de cómo entraron.

### 2.2 Causa raíz

Un "Unauthorized Access Attempt" saliente casi siempre es una de estas:

| Causa | Cómo se confirma |
|---|---|
| Host comprometido (credenciales SSH débiles) | `auth.log` con logins exitosos externos, claves añadidas en `authorized_keys` |
| Malware / botnet | proceso desconocido con conexiones salientes masivas, cron o systemd unit extraño |
| Contenedor o panel expuesto (Docker API, Redis, Jenkins) | servicio administrativo escuchando en 0.0.0.0 |
| Servidor de cliente en hosting compartido | correlación con el rango del cliente |
| Proxy abierto / relay mal configurado | tráfico saliente que espeja tráfico entrante |
| IP suplantada por un tercero | el tráfico no aparece en Akvorado **y** el host está limpio → posible spoofing |

### 2.3 Prevención (semanas siguientes)

**Red**

- **BCP38 / uRPF estricto** en todas las interfaces de cliente y acceso. Elimina de raíz
  la posibilidad de spoofing desde nuestro AS y es lo primero que un ISP pregunta.
- **ACL de salida** que bloquee por defecto los puertos de administración hacia Internet
  desde rangos que no los necesitan (23, 445, 135-139, 1900, 11211, 3389 salvo excepción).
- **Rate-limit de nuevas conexiones por host** en el borde: un servidor legítimo no abre
  cientos de conexiones TCP nuevas por segundo a destinos distintos.

**Detección — cerrar el hueco que dejó pasar esto**

- **Bajar el umbral de FastNetMon para tráfico saliente.** El detector de flujos
  (`ban_for_flows` / `threshold_flows` en la configuración, aplicado a la dirección
  *outgoing*) es el que detecta escaneo; los umbrales de pps/mbps no lo ven. Un host
  interno superando ~500 flujos/s salientes hacia destinos distintos merece alerta.
- **Alerta periódica sobre Akvorado**: programar la consulta de "barrido de red" de
  §1.3 (`destinos > 100` en 1 h sobre puertos de administración) y avisar por correo o
  ticket. Es la consulta que habría detectado este incidente antes que Cogent.
- **Aumentar el TTL de la tabla cruda** de Akvorado de 15 a 30–45 días si el
  almacenamiento lo permite. Los reportes de abuso llegan con días de retraso y con 15
  días la ventana forense se cierra demasiado pronto.
- **Habilitar `TCPFlags`** en el esquema de Akvorado para poder distinguir escaneo
  (SYN sin ACK) de sesiones legítimas.

**Hosts**

- SSH sin autenticación por contraseña (`PasswordAuthentication no`), sólo claves.
- `fail2ban` o CrowdSec en todo lo que exponga SSH/RDP.
- Inventario de servicios expuestos y parcheo; revisión de los paneles de administración.

### 2.4 Proceso de abuso

- Crear una **casilla `abuse@` monitorizada** y un procedimiento de triaje, si aún no
  existe formalmente.
- Registrar cada ticket con: fecha, IP, categoría, host identificado, acción tomada y
  fecha de respuesta. La trazabilidad es lo que evita escalados del upstream.
- Publicar el contacto de abuso correcto en RDAP/WHOIS del rango.

---

## 3. Respuesta a Cogent (plantilla)

Rellenar y enviar por el portal del ticket. Ser concreto: los ISP escalan cuando la
respuesta es genérica.

> **Ticket:** 12172485
> **IP:** 38.3.130.200
>
> We have investigated the reported activity. The IP is assigned to
> `<servidor / cliente / pool NAT>` in our network.
>
> **Findings:** `<qué mostró el análisis de netflow y los logs del host — incluir
> ventana temporal, puertos y destinos observados>`. Root cause was
> `<host comprometido vía credenciales SSH débiles / malware / servicio mal configurado>`.
>
> **Actions taken:**
> - `<fecha>` — host isolated from the network / customer notified.
> - `<fecha>` — system rebuilt, credentials rotated, service patched.
> - `<fecha>` — egress ACL added blocking outbound TCP/22, 23, 3389, 445 from this host.
>
> **Preventive measures:**
> - Strict uRPF (BCP38) enforced on all customer-facing interfaces.
> - Outbound scan detection added to our flow monitoring (Akvorado), alerting on any
>   internal host contacting more than 100 distinct destinations on administrative
>   ports within one hour.
> - FastNetMon outbound flow-rate thresholds lowered to catch low-volume scanning.
> - SSH password authentication disabled; fail2ban deployed.
>
> We consider this incident resolved. Please contact us at `<abuse@dominio>` for any
> further information.

Si el análisis concluye que **no** es nuestro:

> Our flow records (Akvorado, netflow) for the reported window show no traffic from
> 38.3.130.200 matching the reported activity, and the host assigned to this address
> shows no signs of compromise. Note our sampling rate is 1:`<N>`, so low-volume
> traffic may not be captured; we have nevertheless verified the host directly.
> Please provide the original log excerpt with timestamps and timezone so we can
> investigate further. We have strict uRPF enabled on all edge interfaces, which makes
> outbound spoofing from our AS unlikely.

---

## Checklist

- [ ] Abrir el portal y extraer timestamp (con TZ), destino, puerto y reporter
- [ ] Verificar en RDAP que 38.3.130.200 es nuestro
- [ ] Comprobar que el evento cae dentro del TTL de la tabla `flows`
- [ ] Ejecutar las consultas de §1.2 / §1.3 en la ventana correcta
- [ ] Comprobar si existen las columnas NAT (`system.columns ... LIKE '%NAT%'`)
- [ ] Identificar exportador + interfaz + host real (o resolver el NAT con el puerto de origen)
- [ ] Revisar alertas de FastNetMon en esa ventana
- [ ] Contener: aislar el host y/o aplicar ACL de salida
- [ ] Preservar evidencia antes de reinstalar
- [ ] Determinar la causa raíz
- [ ] Aplicar medidas preventivas (§2.3)
- [ ] Responder por el portal dentro de 24–72 h
- [ ] Registrar el ticket en el histórico de abuso

---

## Referencias

- Akvorado — lenguaje de filtro y consola: [`docs/52-console.md`](https://github.com/akvorado/akvorado/blob/main/docs/52-console.md)
- Akvorado — resoluciones y TTL: [`docs/50-configuration.md`](https://github.com/akvorado/akvorado/blob/main/docs/50-configuration.md)
- Akvorado — troubleshooting y tablas de ClickHouse: [`docs/12-troubleshooting.md`](https://github.com/akvorado/akvorado/blob/main/docs/12-troubleshooting.md)
- BCP38 / RFC 2827 — Network Ingress Filtering

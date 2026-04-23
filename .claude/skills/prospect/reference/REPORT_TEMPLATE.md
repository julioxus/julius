# Informe de Exposición de Seguridad: {company_name}

**Clasificación:** CONFIDENCIAL — Preparado exclusivamente para {contact_name}
**Fecha:** {date}
**Preparado por:** {consultant_name} — {consultant_role}
**Dominio analizado:** {domain}

---

## 1. Resumen Ejecutivo

{company_name} presenta una puntuación de seguridad externa de **{grade}** ({score}/100).

Este informe analiza únicamente la **información visible públicamente** sobre la infraestructura de {company_name}. No se ha realizado ningún test intrusivo ni se ha accedido a ningún sistema — toda la información aquí recogida es accesible para cualquier persona (o atacante) en Internet.

**Hallazgos principales:**
- {finding_count} exposiciones identificadas
- {critical_count} de severidad alta que requieren atención inmediata
- {medium_count} de severidad media con corrección recomendada

---

## 2. Puntuación de Seguridad

| Área | Puntuación | Estado |
|------|-----------|--------|
| Cabeceras de seguridad web | {headers_score}/10 | {headers_status} |
| Certificado SSL/TLS | {tls_score}/10 | {tls_status} |
| Configuración de email (SPF/DMARC) | {email_score}/10 | {email_status} |
| Superficie expuesta | {exposure_score}/10 | {exposure_status} |
| Historial de filtraciones | {breach_score}/10 | {breach_status} |
| **TOTAL** | **{total_score}/100** | **{grade}** |

### Escala de puntuación
- **A (90-100):** Excelente — configuración robusta
- **B (75-89):** Buena — mejoras menores recomendadas
- **C (60-74):** Aceptable — varias áreas de mejora
- **D (40-59):** Deficiente — riesgos significativos
- **F (0-39):** Crítica — acción inmediata necesaria

---

## 3. Hallazgos Detallados

### 3.1 Cabeceras de Seguridad Web

Las cabeceras de seguridad son instrucciones que su servidor web envía al navegador del visitante para protegerle. Su ausencia facilita ataques como el robo de sesiones o la inyección de contenido malicioso.

| Cabecera | Estado | Impacto |
|----------|--------|---------|
| Strict-Transport-Security (HSTS) | {hsts_status} | {hsts_impact} |
| Content-Security-Policy (CSP) | {csp_status} | {csp_impact} |
| X-Frame-Options | {xfo_status} | {xfo_impact} |
| X-Content-Type-Options | {xcto_status} | {xcto_impact} |
| Referrer-Policy | {rp_status} | {rp_impact} |
| Permissions-Policy | {pp_status} | {pp_impact} |

**¿Qué significa esto para su negocio?**
{headers_business_impact}

### 3.2 Certificado SSL/TLS

El certificado SSL protege las comunicaciones entre sus clientes y su web. Un certificado caducado o mal configurado muestra advertencias de seguridad en el navegador, ahuyentando clientes y exponiéndoles a interceptación de datos.

- **Protocolo:** {tls_version}
- **Emisor:** {cert_issuer}
- **Válido hasta:** {cert_expiry}
- **Soporte TLS 1.0/1.1 (obsoleto):** {legacy_tls}

**¿Qué significa esto para su negocio?**
{tls_business_impact}

### 3.3 Configuración de Email

Sin protección de email adecuada, un atacante puede enviar correos haciéndose pasar por su empresa (phishing/suplantación), lo que puede resultar en estafas a sus clientes y daño reputacional.

- **SPF (quién puede enviar email como usted):** {spf_status}
- **DMARC (qué hacer con emails fraudulentos):** {dmarc_status}
- **Proveedor de email:** {mail_provider}

**¿Qué significa esto para su negocio?**
{email_business_impact}

### 3.4 Superficie Expuesta

Estos son servicios y subdominios de su organización que son visibles en Internet. Cada servicio expuesto es una puerta de entrada potencial para un atacante.

- **Subdominios detectados:** {subdomain_count}
- **Servicios expuestos:** {exposed_services}
- **Puertos abiertos visibles:** {open_ports}

**Subdominios destacados:**
{notable_subdomains}

**¿Qué significa esto para su negocio?**
{exposure_business_impact}

### 3.5 Historial de Filtraciones

Las filtraciones de datos ocurren cuando los datos de usuarios (emails, contraseñas) de un servicio se hacen públicos por una brecha de seguridad. Si las credenciales de sus empleados aparecen en filtraciones, los atacantes las reutilizan para intentar acceder a sus sistemas.

- **Dominio presente en filtraciones conocidas:** {breach_present}
- **Detalle:** {breach_detail}

**¿Qué significa esto para su negocio?**
{breach_business_impact}

---

## 4. Plan de Acción Recomendado

### Prioridad Alta (1-2 semanas)
{high_priority_actions}

### Prioridad Media (1-3 meses)
{medium_priority_actions}

### Prioridad Baja (mejora continua)
{low_priority_actions}

### Estimación de Coste de Remediación

| Acción | Dificultad | Coste estimado |
|--------|-----------|---------------|
{remediation_cost_table}

---

## 5. Próximos Pasos

Este informe cubre únicamente la **superficie externa visible**. Un análisis completo de seguridad incluiría:

- Auditoría de la aplicación web (pruebas de penetración con autorización)
- Revisión de configuración del servidor y base de datos
- Evaluación de políticas de acceso y contraseñas
- Análisis de cumplimiento normativo (RGPD, LOPD-GDD)
- Formación en concienciación de seguridad para empleados

**¿Interesado en una evaluación completa?**
Ofrezco una llamada gratuita de 15 minutos para revisar estos hallazgos y discutir cómo mejorar la seguridad de {company_name}.

---

**Contacto:**
{consultant_name}
{consultant_role}
Email: {consultant_email}
Web: {consultant_website}

---

*Nota: Este informe se ha elaborado exclusivamente con información de acceso público. No se ha realizado ningún test intrusivo ni se ha accedido a ningún sistema protegido. La información se proporciona de buena fe para ayudar a mejorar la postura de seguridad de {company_name}.*

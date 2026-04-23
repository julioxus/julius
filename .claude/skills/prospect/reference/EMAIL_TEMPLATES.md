# Email Templates — Prospecting

## Template 1: Email Inicial (tras generar informe)

**Asunto:** Análisis de seguridad externo de {company_name} — hallazgos relevantes

---

Estimado/a {contact_name},

Me llamo {consultant_name}, soy {consultant_role}. Me pongo en contacto con usted porque he realizado un análisis rutinario de la superficie pública de {company_name} como parte de un estudio de seguridad del sector {sector} en la zona.

He identificado {finding_count} áreas de mejora en la configuración externa de {domain}. Le destaco dos que considero prioritarias:

{teaser_finding_1}

{teaser_finding_2}

Estos datos son visibles para cualquier persona en Internet, lo que significa que un atacante motivado también puede verlos. La buena noticia es que la mayoría tiene solución sencilla.

He preparado un informe detallado con las {finding_count} observaciones, puntuación de seguridad y un plan de acción priorizado. Se lo envío adjunto sin compromiso.

Si le interesa, le ofrezco una llamada de 15 minutos para revisarlo juntos y responder cualquier duda. Puede reservar directamente aquí: {calendar_link}

Un saludo,

{consultant_name}
{consultant_role}
{consultant_email}
{consultant_phone}

---

## Template 2: Follow-up (7 días después, si no hay respuesta)

**Asunto:** Re: Análisis de seguridad de {company_name}

---

Estimado/a {contact_name},

Le escribo brevemente para asegurarme de que recibió el informe de seguridad que le envié la semana pasada sobre {domain}.

Desde entonces, {followup_hook}

Quedo a su disposición para una breve llamada si le resulta útil. Sin ningún compromiso.

Un saludo,

{consultant_name}

---

## Template 3: Propuesta tras llamada (si hay interés)

**Asunto:** Propuesta de auditoría de seguridad — {company_name}

---

Estimado/a {contact_name},

Gracias por su tiempo en nuestra conversación del {call_date}. Como comentamos, le envío una propuesta para la auditoría de seguridad de {company_name}.

### Alcance propuesto

**Fase 1 — Auditoría externa (1-2 días)**
- Test de penetración de la aplicación web ({domain})
- Análisis de configuración de servidores y servicios expuestos
- Revisión de seguridad del correo electrónico
- Entregable: Informe técnico + ejecutivo con hallazgos y remediación

**Fase 2 — Auditoría interna (opcional, 2-3 días)**
- Revisión de políticas de acceso y contraseñas
- Análisis de configuración de red interna
- Evaluación de cumplimiento RGPD/LOPD-GDD
- Formación básica para empleados (1 sesión de 2h)

### Inversión

| Servicio | Precio |
|----------|--------|
| Fase 1 — Auditoría externa | {price_phase1} € + IVA |
| Fase 2 — Auditoría interna | {price_phase2} € + IVA |
| Paquete completo (Fase 1 + 2) | {price_bundle} € + IVA |
| Mantenimiento trimestral (opcional) | {price_maintenance} €/trimestre + IVA |

### Condiciones
- Contrato de confidencialidad (NDA) incluido
- Seguro de responsabilidad civil profesional
- Inicio disponible a partir del {availability_date}
- Informe entregado en un máximo de 5 días laborables tras finalizar las pruebas

¿Le parece bien que concretemos una fecha de inicio?

Un saludo,

{consultant_name}
{consultant_role}
{consultant_email}

---

## Notas de uso

**Personalización obligatoria antes de enviar:**
- Revisar tono según el sector (más formal para legal/banca, más cercano para hostelería/comercio)
- Verificar que los findings del teaser son reales y están en el informe
- Ajustar precios según complejidad del dominio y tamaño de empresa
- Añadir calendario link real (Calendly/Cal.com)

**Hooks de follow-up (para {followup_hook}):**
- "he notado que el certificado SSL de {domain} caduca en X días"
- "se ha publicado una nueva vulnerabilidad que afecta a {technology} (el CMS que utiliza su web)"
- "el sector {sector} ha sido objetivo de una campaña de phishing reciente"
- "he actualizado el informe con datos nuevos sobre filtraciones que afectan a su dominio"

**No enviar si:**
- La empresa tiene un CISO o equipo de seguridad visible (LinkedIn check) — contactar directamente al CISO con otro enfoque
- El dominio es un simple redirect a redes sociales (no hay infraestructura que auditar)
- La empresa está en proceso de cierre o tiene web "en construcción"

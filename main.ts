// === SSL Checker API en Deno Deploy ===
// Obtiene IP, fechas del certificado, validez y si tiene HTTPS.

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const host = url.searchParams.get("host");
  const port = Number(url.searchParams.get("port") || 443);

  const headers = {
    "content-type": "application/json",
    "access-control-allow-origin": "*", // Para usar desde n8n o navegador
  };

  if (!host) {
    return new Response(JSON.stringify({ error: "Falta el parámetro 'host'" }), {
      headers,
      status: 400,
    });
  }

  try {
    // Resolución DNS
    const ips = await Deno.resolveDns(host, "A");
    const ip = ips?.[0] ?? null;

    // Abrir conexión TLS para leer certificado
    const conn = await Deno.connectTls({ hostname: host, port });
    const cert = conn.tlsInfo?.peerCertificateChain?.[0];
    conn.close();

    if (!cert) throw new Error("No se pudo obtener el certificado SSL.");

    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    const now = new Date();
    const msRemaining = validTo.getTime() - now.getTime();
    const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));
    const isValidNow = validFrom <= now && now <= validTo;

    const data = {
      ip,
      host,
      port,
      valid_from: cert.validFrom,
      valid_to: cert.validTo,
      days_remaining: daysRemaining,
      issuer: cert.issuer?.commonName ?? cert.issuer?.organization ?? null,
      subject: cert.subject?.commonName ?? null,
      is_valid_now: isValidNow,
      has_https: true,
    };

    return new Response(JSON.stringify(data, null, 2), { headers });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: err.message,
        has_https: false,
      }),
      { headers, status: 500 }
    );
  }
});

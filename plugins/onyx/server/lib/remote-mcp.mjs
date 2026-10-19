import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

export class ConnectorFailure extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ConnectorFailure";
    this.code = code;
  }
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new ConnectorFailure("timeout", `${label} timed out after ${timeoutMs} ms`)),
      timeoutMs,
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function sanitizeError(error, secret) {
  let message = error instanceof Error ? error.message : String(error);
  if (secret) message = message.split(secret).join("[REDACTED]");
  return message.slice(0, 1000);
}

export async function openConnectorSession(connector, callback, environment = process.env) {
  const envVar = connector.transport.auth.env_var;
  const token = environment[envVar];
  if (!token) {
    throw new ConnectorFailure("missing_auth", `${envVar} is not configured`);
  }

  const client = new Client(
    { name: "security-code-audit-onyx-adapter", version: "0.1.0" },
    {
      capabilities: {},
    },
  );
  const transport = new StreamableHTTPClientTransport(new URL(connector.transport.url), {
    requestInit: {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  });
  const connectTimeout = connector.timeouts?.connect_ms ?? 5000;

  try {
    await withTimeout(client.connect(transport), connectTimeout, `${connector.id} connection`);
    const listed = await withTimeout(client.listTools(), connectTimeout, `${connector.id} tool discovery`);
    return await callback({
      tools: listed.tools ?? [],
      callTool: (request) =>
        withTimeout(
          client.callTool(request),
          connector.timeouts?.tool_ms ?? 20000,
          `${connector.id}.${request.name}`,
        ),
    });
  } catch (error) {
    if (error instanceof ConnectorFailure) throw error;
    throw new ConnectorFailure("unavailable", sanitizeError(error, token));
  } finally {
    try {
      await client.close();
    } catch {
      // The remote endpoint may fail before the transport becomes closable.
    }
  }
}

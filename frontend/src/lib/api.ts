export type ApiEnvelope<T> = {
  status: "ok" | "error";
  message: string;
  data: T;
};

async function request<T>(path: string, init?: RequestInit): Promise<ApiEnvelope<T>> {
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  const payload = (await response.json()) as ApiEnvelope<T>;
  if (!response.ok || payload.status === "error") {
    throw new Error(payload.message || "Request failed");
  }

  return payload;
}

export function getJson<T>(path: string) {
  return request<T>(path, { method: "GET" });
}

export function postJson<T>(path: string, body?: unknown) {
  return request<T>(path, {
    method: "POST",
    body: body ? JSON.stringify(body) : undefined,
  });
}

export function deleteJson<T>(path: string) {
  return request<T>(path, { method: "DELETE" });
}

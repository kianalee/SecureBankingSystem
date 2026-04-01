export type ApiEnvelope<T> = {
  status: "ok" | "error";
  message: string;
  data: T;
};

const ATM_SESSION_STORAGE_KEY = "securebank.atmSessionToken";

function getAtmSessionToken() {
  if (typeof window === "undefined") {
    return null;
  }

  return window.sessionStorage.getItem(ATM_SESSION_STORAGE_KEY);
}

export function setAtmSessionToken(token: string | null) {
  if (typeof window === "undefined") {
    return;
  }

  if (!token) {
    window.sessionStorage.removeItem(ATM_SESSION_STORAGE_KEY);
    return;
  }

  window.sessionStorage.setItem(ATM_SESSION_STORAGE_KEY, token);
}

async function request<T>(path: string, init?: RequestInit): Promise<ApiEnvelope<T>> {
  const atmSessionToken = getAtmSessionToken();
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(atmSessionToken ? { "X-Session": atmSessionToken } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  const payload = (await response.json()) as ApiEnvelope<T>;
  if (response.status === 401 && path.startsWith("/api/")) {
    setAtmSessionToken(null);
  }
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

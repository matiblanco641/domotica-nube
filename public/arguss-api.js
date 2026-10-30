
const ARGUSS_API = {
  token: localStorage.getItem("arguss_token"),

  async request(endpoint, options = {}) {
    const response = await fetch(endpoint, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(this.token
          ? { Authorization: `Bearer ${this.token}` }
          : {}),
        ...options.headers
      }
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Error de conexión");
    }

    return data;
  },

  async register(email, password) {
    const data = await this.request("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    this.saveToken(data.token);
    return data;
  },

  async login(email, password) {
    const data = await this.request("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    this.saveToken(data.token);
    return data;
  },

  saveToken(token) {
    this.token = token;
    localStorage.setItem("arguss_token", token);
  },

  logout() {
    this.token = null;
    localStorage.removeItem("arguss_token");
  },

  async getRooms() {
    return await this.request("/api/rooms");
  },

  async saveRoom(roomKey, state) {
    return await this.request(
      `/api/rooms/${encodeURIComponent(roomKey)}/state`,
      {
        method: "PUT",
        body: JSON.stringify({ state })
      }
    );
  },

  async getHistory() {
    return await this.request("/api/history");
  },

  async getUser() {
    return await this.request("/api/me");
  }
};

window.ARGUSS_API = ARGUSS_API;

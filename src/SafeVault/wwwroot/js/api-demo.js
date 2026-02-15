(() => {
    const output = document.getElementById("api-output");
    const accessToken = document.getElementById("access-token");
    const refreshToken = document.getElementById("refresh-token");

    const setOutput = (title, status, payload) => {
        output.textContent = `${title}\nStatus: ${status}\n\n${JSON.stringify(payload, null, 2)}`;
    };

    const getJson = async (response) => {
        try {
            return await response.json();
        } catch {
            return { message: "No JSON body returned." };
        }
    };

    const authHeader = () => {
        if (!accessToken.value.trim()) {
            return {};
        }

        return {
            Authorization: `Bearer ${accessToken.value.trim()}`
        };
    };

    document.getElementById("btn-register")?.addEventListener("click", async () => {
        const payload = {
            username: document.getElementById("register-username").value,
            email: document.getElementById("register-email").value,
            password: document.getElementById("register-password").value,
            role: "User"
        };

        const response = await fetch("/api/auth/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const body = await getJson(response);
        setOutput("Register", response.status, body);
    });

    document.getElementById("btn-login")?.addEventListener("click", async () => {
        const payload = {
            username: document.getElementById("login-username").value,
            password: document.getElementById("login-password").value
        };

        const response = await fetch("/api/auth/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const body = await getJson(response);
        if (response.ok) {
            accessToken.value = body.accessToken ?? "";
            refreshToken.value = body.refreshToken ?? "";
        }

        setOutput("Login", response.status, body);
    });

    document.getElementById("btn-refresh")?.addEventListener("click", async () => {
        const response = await fetch("/api/auth/refresh", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ refreshToken: refreshToken.value })
        });

        const body = await getJson(response);
        if (response.ok) {
            accessToken.value = body.accessToken ?? "";
            refreshToken.value = body.refreshToken ?? "";
        }

        setOutput("Refresh", response.status, body);
    });

    const callProtectedEndpoint = async (title, endpoint) => {
        const response = await fetch(endpoint, {
            headers: {
                ...authHeader()
            }
        });

        const body = await getJson(response);
        setOutput(title, response.status, body);
    };

    document.getElementById("btn-user")?.addEventListener("click", () => callProtectedEndpoint("User Profile", "/api/user/profile"));
    document.getElementById("btn-admin")?.addEventListener("click", () => callProtectedEndpoint("Admin Dashboard", "/api/admin/dashboard"));
    document.getElementById("btn-guest")?.addEventListener("click", () => callProtectedEndpoint("Guest Welcome", "/api/guest/welcome"));
})();
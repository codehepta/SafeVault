(() => {
    const rows = document.querySelectorAll(".vault-table tbody tr");
    const tokenInput = document.querySelector("#vault-secret-token-form input[name='__RequestVerificationToken']");

    const secretCache = new Map();

    const fallbackCopy = (text) => {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "absolute";
        area.style.left = "-9999px";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        document.body.removeChild(area);
    };

    const getSecretForEntry = async (entryId) => {
        if (secretCache.has(entryId)) {
            return secretCache.get(entryId);
        }

        const response = await fetch("/Home/GetPasswordSecret", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "RequestVerificationToken": tokenInput?.value ?? ""
            },
            body: new URLSearchParams({ id: entryId })
        });

        if (!response.ok) {
            throw new Error("Unable to read secret");
        }

        const payload = await response.json();
        const secret = payload.secret ?? payload.Secret ?? "";
        secretCache.set(entryId, secret);
        return secret;
    };

    rows.forEach((row) => {
        const secretElement = row.querySelector(".secret-value");
        const toggleButton = row.querySelector(".btn-toggle-secret");
        const copyButton = row.querySelector(".btn-copy-secret");

        if (!secretElement || !toggleButton || !copyButton) {
            return;
        }

        const entryId = secretElement.dataset.entryId;
        let visible = false;

        toggleButton.addEventListener("click", async () => {
            if (!entryId) {
                return;
            }

            visible = !visible;
            if (!visible) {
                secretElement.textContent = secretElement.dataset.masked ?? "";
                toggleButton.textContent = "Show";
                return;
            }

            try {
                const secret = await getSecretForEntry(entryId);
                secretElement.textContent = secret;
                toggleButton.textContent = "Hide";
            } catch {
                visible = false;
                toggleButton.textContent = "Show";
            }
        });

        copyButton.addEventListener("click", async () => {
            if (!entryId) {
                return;
            }

            try {
                const secret = await getSecretForEntry(entryId);
                if (!secret) {
                    return;
                }

                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(secret);
                } else {
                    fallbackCopy(secret);
                }

                const originalText = copyButton.textContent;
                copyButton.textContent = "Copied";
                window.setTimeout(() => {
                    copyButton.textContent = originalText;
                }, 1200);
            } catch {
                copyButton.textContent = "Copy failed";
            }
        });
    });
})();

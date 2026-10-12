const sessionsMessage = document.getElementById("sessionsMessage");
const sessionsList = document.getElementById("sessionsList");
const signOutOtherDevicesButton = document.getElementById("signOutOtherDevices");

function formatSessionDate(value) {
    if (!value) {
        return "Date unavailable";
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? "Date unavailable"
        : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

async function loadSessions() {
    sessionsMessage.textContent = "Loading signed-in devices…";
    try {
        const data = await SecureDeskErrors.requestJson(
            "/api/auth/sessions",
            undefined,
            "We couldn't load your signed-in devices. Please refresh the page."
        );
        sessionsList.replaceChildren();

        for (const session of data.sessions) {
            const item = document.createElement("li");
            const title = document.createElement("div");
            title.className = "session-title";

            const deviceName = document.createElement("span");
            deviceName.textContent = session.deviceName || "Signed-in device";
            title.append(deviceName);
            if (session.isCurrent) {
                const current = document.createElement("span");
                current.textContent = "This device";
                title.append(current);
            }

            const details = document.createElement("span");
            details.className = "session-details";
            const signedIn = session.signedInAt
                ? `Signed in ${formatSessionDate(session.signedInAt)}`
                : "Previously signed in";
            details.textContent = `${signedIn}${session.ipAddress ? ` · ${session.ipAddress}` : ""}`;
            item.append(title, details);

            if (!session.isCurrent) {
                const revokeButton = document.createElement("button");
                revokeButton.className = "session-revoke";
                revokeButton.type = "button";
                revokeButton.textContent = "Sign out this device";
                revokeButton.addEventListener("click", async () => {
                    revokeButton.disabled = true;
                    try {
                        const result = await SecureDeskErrors.requestJson(
                            `/api/auth/sessions/${encodeURIComponent(session.id)}`,
                            { method: "DELETE" },
                            "We couldn't sign out that device. Please try again."
                        );
                        sessionsMessage.textContent = result.message;
                        await loadSessions();
                    } catch (error) {
                        sessionsMessage.textContent = SecureDeskErrors.message(
                            error,
                            "We couldn't sign out that device. Please try again."
                        );
                        revokeButton.disabled = false;
                    }
                });
                item.append(revokeButton);
            }

            sessionsList.append(item);
        }

        sessionsMessage.textContent = data.sessions.length
            ? "Review devices that can access your account. Sign out any you no longer use."
            : "No active devices found.";
        signOutOtherDevicesButton.disabled = !data.sessions.some((session) => !session.isCurrent);
    } catch (error) {
        sessionsMessage.textContent = SecureDeskErrors.message(
            error,
            "We couldn't load your signed-in devices. Please refresh the page."
        );
    }
}

signOutOtherDevicesButton.addEventListener("click", async () => {
    signOutOtherDevicesButton.disabled = true;
    try {
        const result = await SecureDeskErrors.requestJson(
            "/api/auth/sessions",
            { method: "DELETE" },
            "We couldn't sign out your other devices. Please try again."
        );
        sessionsMessage.textContent = result.message;
        await loadSessions();
    } catch (error) {
        sessionsMessage.textContent = SecureDeskErrors.message(
            error,
            "We couldn't sign out your other devices. Please try again."
        );
        signOutOtherDevicesButton.disabled = false;
    }
});

loadSessions();

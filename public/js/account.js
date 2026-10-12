const accountCard = document.querySelector(".account-card");
const requiredRole = accountCard.dataset.requiredRole;
const errorMessage = document.getElementById("accountError");
const activityMessage = document.getElementById("activityMessage");
const activityList = document.getElementById("activityList");

function formatDate(value) {
    if (!value) {
        return "Not available";
    }

    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? "Not available"
        : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

async function loadActivity() {
    try {
        const data = await SecureDeskErrors.requestJson(
            "/api/auth/activity",
            undefined,
            "We couldn't load your recent activity."
        );

        activityList.replaceChildren();
        if (!data.activity.length) {
            activityMessage.textContent = "No recent account activity.";
            return;
        }

        activityMessage.textContent = "";
        for (const activity of data.activity) {
            const item = document.createElement("li");
            const label = document.createElement("span");
            const timestamp = document.createElement("time");
            const route = activity.method && activity.path
                ? `${activity.method} ${activity.path}`
                : activity.action.replaceAll(".", " ");

            label.textContent = `${route}${activity.statusCode ? ` · ${activity.statusCode}` : ""}`;
            timestamp.dateTime = activity.occurredAt;
            timestamp.textContent = formatDate(activity.occurredAt);
            item.append(label, timestamp);
            activityList.append(item);
        }
    } catch (error) {
        activityMessage.textContent = SecureDeskErrors.message(
            error,
            "We couldn't load your recent activity. Refresh the page to try again."
        );
    }
}

async function loadAccount() {
    try {
        const data = await SecureDeskErrors.requestJson(
            "/api/auth/me",
            undefined,
            "We couldn't load your account. Refresh the page to try again."
        );
        if (!data.user) {
            window.location.replace("/login.html");
            return;
        }
        if (requiredRole === "admin" && data.user.role !== "admin") {
            window.location.replace("/dashboard.html");
            return;
        }
        if (requiredRole === "user" && data.user.role === "admin") {
            window.location.replace("/admin.html");
            return;
        }
        document.getElementById("welcomeUsername").textContent = data.user.username || "there";
        document.getElementById("accountEmail").textContent = data.user.email;
        document.getElementById("accountRole").textContent = data.user.role;
        document.getElementById("lastSeenAt").textContent = formatDate(data.lastSeenAt);
        await loadActivity();
    } catch (error) {
        if (error.status === 401) {
            window.location.replace("/login.html");
            return;
        }
        errorMessage.textContent = SecureDeskErrors.message(
            error,
            "We couldn't load your account. Check your connection and refresh."
        );
    }
}

const logoutButton = document.getElementById("logoutButton");
logoutButton.addEventListener("click", async () => {
    logoutButton.disabled = true;
    logoutButton.textContent = "Signing out…";
    try {
        await SecureDeskErrors.requestJson(
            "/api/auth/logout",
            { method: "POST" },
            "We couldn't sign you out. Please try again."
        );
        window.location.replace("/login.html");
    } catch (error) {
        errorMessage.textContent = SecureDeskErrors.message(error, "We couldn't sign you out. Please try again.");
        logoutButton.disabled = false;
        logoutButton.textContent = "Sign out";
    }
});

loadAccount();

const accountCard = document.querySelector(".account-card");
const errorMessage = document.getElementById("accountError");
const activityMessage = document.getElementById("activityMessage");
const activityList = document.getElementById("activityList");
const PAGE_SIZE = 25;
const pagination = {
    users: 1,
    logs: 1
};

function formatDate(value) {
    if (!value) {
        return "Not available";
    }

    const date = new Date(value);
    return Number.isNaN(date.getTime())
        ? "Not available"
        : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

async function fetchJson(url) {
    return SecureDeskErrors.requestJson(
        url,
        undefined,
        "We couldn't load this information. Please try again."
    );
}

async function loadActivity() {
    try {
        const data = await fetchJson("/api/auth/activity");
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
            "We couldn't load recent activity. Please refresh the page to try again."
        );
    }
}

function setPaginationControls(kind, data) {
    const pageCount = Math.max(1, Math.ceil(data.total / data.limit));
    const label = document.getElementById(`${kind}Page`);
    const previous = document.getElementById(`${kind}Previous`);
    const next = document.getElementById(`${kind}Next`);
    label.textContent = `Page ${data.page} of ${pageCount}`;
    previous.disabled = data.page <= 1;
    next.disabled = data.page >= pageCount;
}

function appendCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = value === null || value === undefined || value === ""
        ? "—"
        : String(value);
    row.append(cell);
}

async function loadUsers() {
    const message = document.getElementById("usersMessage");
    const tableBody = document.getElementById("usersTableBody");
    message.textContent = "Loading account data…";
    try {
        const data = await fetchJson(`/api/admin/users?page=${pagination.users}&limit=${PAGE_SIZE}`);
        tableBody.replaceChildren();
        for (const user of data.users) {
            const row = document.createElement("tr");
            appendCell(row, user.username);
            appendCell(row, user.email);
            appendCell(row, user.role);
            appendCell(row, user.is_active ? "Active" : "Inactive");
            appendCell(row, user.two_factor_enabled ? "Enabled" : "Disabled");
            appendCell(row, formatDate(user.last_seen_at));
            appendCell(row, formatDate(user.created_at));
            tableBody.append(row);
        }

        message.textContent = data.total
            ? `Showing ${data.users.length ? (data.page - 1) * data.limit + 1 : 0}–${(data.page - 1) * data.limit + data.users.length} of ${data.total} accounts.`
            : "No accounts found.";
        setPaginationControls("users", data);
    } catch (error) {
        tableBody.replaceChildren();
        message.textContent = SecureDeskErrors.message(
            error,
            "We couldn't load account data. Please try again."
        );
    }
}

async function loadLogs() {
    const message = document.getElementById("logsMessage");
    const tableBody = document.getElementById("logsTableBody");
    message.textContent = "Loading audit logs…";
    try {
        const data = await fetchJson(`/api/admin/audit-logs?page=${pagination.logs}&limit=${PAGE_SIZE}`);
        tableBody.replaceChildren();
        for (const log of data.logs) {
            const row = document.createElement("tr");
            appendCell(row, formatDate(log.created_at));
            appendCell(row, log.username || log.user_id || "Unauthenticated");
            appendCell(row, log.action);
            appendCell(row, log.method && log.path ? `${log.method} ${log.path}` : "—");
            appendCell(row, log.status_code);
            appendCell(row, log.ip_address);
            appendCell(row, log.user_agent);
            tableBody.append(row);
        }

        message.textContent = data.total
            ? `Showing ${data.logs.length ? (data.page - 1) * data.limit + 1 : 0}–${(data.page - 1) * data.limit + data.logs.length} of ${data.total} events.`
            : "No audit events found.";
        setPaginationControls("logs", data);
    } catch (error) {
        tableBody.replaceChildren();
        message.textContent = SecureDeskErrors.message(
            error,
            "We couldn't load audit logs. Please try again."
        );
    }
}

async function loadAccount() {
    try {
        const data = await fetchJson("/api/auth/me");
        if (accountCard.dataset.requiredRole === "admin" && data.user.role !== "admin") {
            window.location.replace("/dashboard.html");
            return;
        }

        document.getElementById("welcomeUsername").textContent = data.user.username || "there";
        document.getElementById("accountEmail").textContent = data.user.email;
        document.getElementById("accountRole").textContent = data.user.role;
        document.getElementById("lastSeenAt").textContent = formatDate(data.lastSeenAt);
        await Promise.all([loadActivity(), loadUsers(), loadLogs()]);
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

for (const kind of ["users", "logs"]) {
    document.getElementById(`${kind}Previous`).addEventListener("click", () => {
        pagination[kind] = Math.max(1, pagination[kind] - 1);
        (kind === "users" ? loadUsers : loadLogs)();
    });
    document.getElementById(`${kind}Next`).addEventListener("click", () => {
        pagination[kind] += 1;
        (kind === "users" ? loadUsers : loadLogs)();
    });
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

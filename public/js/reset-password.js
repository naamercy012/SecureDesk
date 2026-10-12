const form = document.getElementById("resetPasswordForm");
const errorMessage = document.getElementById("errorMessage");
const resetToken = new URLSearchParams(window.location.search).get("token");

if (resetToken) {
    window.history.replaceState(null, "", window.location.pathname);
} else {
    errorMessage.textContent = "This reset link is missing or incomplete. Request a new link to continue.";
    form.querySelector("button[type='submit']").disabled = true;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorMessage.textContent = "";

    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    if (password !== confirmPassword) {
        errorMessage.textContent = "Those passwords don't match. Check both fields and try again.";
        return;
    }

    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    button.textContent = "Updating…";

    try {
        const data = await SecureDeskErrors.requestJson(
            "/api/auth/password-reset/complete",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: resetToken, password })
            },
            "We couldn't update your password. Request a new reset link and try again."
        );
        window.location.replace("/login.html?password-reset=complete");
    } catch (error) {
        errorMessage.textContent = SecureDeskErrors.message(
            error,
            "We couldn't update your password. Request a new reset link and try again."
        );
        button.disabled = false;
        button.textContent = "Update password";
    }
});

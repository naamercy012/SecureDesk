const form = document.getElementById("loginForm");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const errorMessage = document.getElementById("errorMessage");
const togglePassword = document.getElementById("togglePassword");

if (new URLSearchParams(window.location.search).has("registered")) {
    errorMessage.textContent = "Your account is ready. Sign in to continue.";
    errorMessage.style.color = "#267044";
}
if (new URLSearchParams(window.location.search).get("password-reset") === "complete") {
    errorMessage.textContent = "Your password has been updated. Sign in with your new password and authenticator code.";
    errorMessage.style.color = "#267044";
}

if (togglePassword && passwordInput) {
    togglePassword.addEventListener("click", () => {
        const showPassword = passwordInput.type === "password";
        passwordInput.type = showPassword ? "text" : "password";
        togglePassword.textContent = showPassword ? "Hide" : "Show";
        togglePassword.setAttribute("aria-pressed", String(showPassword));
    });
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorMessage.textContent = "";

    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    button.textContent = "Signing in...";

    try {
        const data = await SecureDeskErrors.requestJson("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: usernameInput.value.trim(),
                password: passwordInput.value
            })
        }, "We couldn't sign you in. Please check your details and try again.");

        if (data.requires2FA) {
            window.location.assign("/verify-2fa.html");
            return;
        }

        if (!data.user || !data.user.role) {
            throw new Error("We couldn't finish signing you in. Please try again.");
        }

        window.location.assign(data.user.role === "admin" ? "/admin.html" : "/dashboard.html");
    } catch (error) {
        errorMessage.style.color = "";
        errorMessage.textContent = SecureDeskErrors.message(error, "We couldn't sign you in. Please check your details and try again.");
        button.disabled = false;
        button.textContent = "Sign in";
    }
});

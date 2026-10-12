const form = document.getElementById("registerForm");
const errorMessage = document.getElementById("errorMessage");

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorMessage.textContent = "";

    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    button.textContent = "Creating account...";

    try {
        const username = document.getElementById("username").value.trim();
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;
        const data = await SecureDeskErrors.requestJson("/api/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password })
        }, "We couldn't create your account. Please try again.");

        if (!data.requires2FA) {
            throw new Error("We couldn't start account verification. Please try again.");
        }

        if (data.qrCodeDataUrl) {
            sessionStorage.setItem("totpSetupMode", "true");
            sessionStorage.setItem("totpQrCode", data.qrCodeDataUrl);
        }

        window.location.assign("/verify-2fa.html");
    } catch (error) {
        errorMessage.textContent = SecureDeskErrors.message(error, "We couldn't create your account. Please try again.");
        button.disabled = false;
        button.textContent = "Create account";
    }
});

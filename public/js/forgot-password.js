const form = document.getElementById("forgotPasswordForm");
const errorMessage = document.getElementById("errorMessage");
const successMessage = document.getElementById("successMessage");

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorMessage.textContent = "";
    successMessage.textContent = "";

    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    button.textContent = "Sending…";

    try {
        const data = await SecureDeskErrors.requestJson(
            "/api/auth/password-reset/request",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: document.getElementById("email").value.trim() })
            },
            "We couldn't send a reset link. Please try again."
        );
        successMessage.textContent = data.message;
        form.reset();
    } catch (error) {
        errorMessage.textContent = SecureDeskErrors.message(
            error,
            "We couldn't send a reset link. Please try again."
        );
    } finally {
        button.disabled = false;
        button.textContent = "Send reset link";
    }
});

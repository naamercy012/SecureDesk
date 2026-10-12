const form = document.getElementById("verifyForm");
const codeInput = document.getElementById("code");
const errorMessage = document.getElementById("errorMessage");
const resendButton = document.getElementById("resendCode");
const totpSetupPanel = document.getElementById("totpSetupPanel");
const qrCodeImage = document.getElementById("totpQrCode");
const recoveryCodesPanel = document.getElementById("recoveryCodesPanel");
const recoveryCodesList = document.getElementById("recoveryCodesList");
const copyRecoveryCodesButton = document.getElementById("copyRecoveryCodes");
const continueAfterRecoveryCodesButton = document.getElementById("continueAfterRecoveryCodes");
let enrolledUserRole = "user";

const setupMode = sessionStorage.getItem("totpSetupMode") === "true";
const qrCodeDataUrl = sessionStorage.getItem("totpQrCode");

if (setupMode && qrCodeDataUrl) {
    qrCodeImage.src = qrCodeDataUrl;
    qrCodeImage.alt = "QR code for TOTP setup";
    totpSetupPanel.classList.remove("hidden");
}

if (!setupMode) {
    resendButton.classList.add("hidden");
    resendButton.disabled = true;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorMessage.textContent = "";
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    button.textContent = "Verifying...";

    try {
        const data = await SecureDeskErrors.requestJson("/api/auth/verify-2fa", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: codeInput.value.trim() })
        }, "We couldn't verify that code. Please try again.");
        if (!data.user || !data.user.role) {
            throw new Error("We couldn't finish verification. Please try again.");
        }

        if (setupMode) {
            sessionStorage.removeItem("totpSetupMode");
            sessionStorage.removeItem("totpQrCode");
        }

        if (Array.isArray(data.recoveryCodes) && data.recoveryCodes.length > 0) {
            enrolledUserRole = data.user.role;
            form.classList.add("hidden");
            totpSetupPanel.classList.add("hidden");
            recoveryCodesList.textContent = data.recoveryCodes.join("\n");
            recoveryCodesPanel.classList.remove("hidden");
            return;
        }

        window.location.assign(data.user.role === "admin" ? "/admin.html" : "/dashboard.html");
    } catch (error) {
        errorMessage.textContent = SecureDeskErrors.message(error, "We couldn't verify that code. Please try again.");
        button.disabled = false;
        button.textContent = "Verify and continue";
    }
});

copyRecoveryCodesButton.addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(recoveryCodesList.textContent);
        copyRecoveryCodesButton.textContent = "Copied";
    } catch (error) {
        errorMessage.textContent = "We couldn't copy the codes automatically. Select and copy them manually.";
    }
});

continueAfterRecoveryCodesButton.addEventListener("click", () => {
    window.location.assign(enrolledUserRole === "admin" ? "/admin.html" : "/dashboard.html");
});

if (setupMode) {
    resendButton.addEventListener("click", async () => {
        resendButton.disabled = true;
        errorMessage.style.color = "";
        errorMessage.textContent = "Your authenticator app creates these codes. Open the app and use its current six-digit code.";
    });
}

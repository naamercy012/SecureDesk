(function () {
    function createError(message, status) {
        const error = new Error(message);
        error.status = status;
        return error;
    }

    async function requestJson(url, options, fallbackMessage) {
        let response;
        try {
            response = await fetch(url, options);
        } catch {
            throw createError("We couldn't connect. Check your internet connection and try again.");
        }

        let data;
        try {
            data = await response.json();
        } catch {
            if (!response.ok) {
                throw createError(
                    response.status >= 500
                        ? "Something went wrong on our end. Please try again in a moment."
                        : "We couldn't complete that request. Please try again.",
                    response.status
                );
            }
            throw createError(fallbackMessage);
        }

        if (!data || typeof data !== "object") {
            throw createError(
                response.ok
                    ? fallbackMessage
                    : response.status >= 500
                        ? "Something went wrong on our end. Please try again in a moment."
                        : "We couldn't complete that request. Please try again.",
                response.status
            );
        }

        if (!response.ok) {
            const message = typeof data.message === "string" && data.message.trim()
                ? data.message
                : response.status >= 500
                    ? "Something went wrong on our end. Please try again in a moment."
                    : "We couldn't complete that request. Please try again.";
            throw createError(message, response.status);
        }

        return data;
    }

    function message(error, fallbackMessage) {
        if (error && error.status === 429) {
            return error.message || "Too many attempts. Please wait a little while and try again.";
        }
        if (error && error.status >= 500) {
            return "Something went wrong on our end. Please try again in a moment.";
        }
        if (error && typeof error.message === "string" && error.message.trim()) {
            return error.message;
        }
        return fallbackMessage;
    }

    window.SecureDeskErrors = { requestJson, message };
})();

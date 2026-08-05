/*
 * © AI WebScapes 2026
 */

(() => {
  "use strict";

  const navToggle = document.querySelector(".nav-toggle");
  const navMenu = document.querySelector("#primary-menu");
  const demoForm = document.querySelector("#demo-form");
  const formStatus = document.querySelector("#form-status");

  const setStatus = (message, type = "") => {
    if (!formStatus) return;

    formStatus.textContent = message;
    formStatus.className = "form-status";

    if (type) {
      formStatus.classList.add(type);
    }
  };

  const clearFieldErrors = (form) => {
    form.querySelectorAll(".field-error").forEach((field) => {
      field.classList.remove("field-error");
      field.removeAttribute("aria-invalid");
    });
  };

  const markFieldErrors = (form, errors) => {
    Object.keys(errors).forEach((name) => {
      const field = form.querySelector(`[name="${CSS.escape(name)}"]`);

      if (field) {
        field.classList.add("field-error");
        field.setAttribute("aria-invalid", "true");
      }
    });
  };

  if (navToggle && navMenu) {
    navToggle.addEventListener("click", () => {
      const isOpen = navMenu.classList.toggle("is-open");
      navToggle.setAttribute("aria-expanded", String(isOpen));
    });

    navMenu.addEventListener("click", (event) => {
      if (event.target instanceof HTMLAnchorElement) {
        navMenu.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  if (demoForm) {
    demoForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      clearFieldErrors(demoForm);
      setStatus("Submitting request...");

      const submitButton = demoForm.querySelector('button[type="submit"]');

      if (submitButton) {
        submitButton.disabled = true;
      }

      try {
        const response = await fetch(demoForm.action, {
          method: "POST",
          body: new FormData(demoForm),
          credentials: "same-origin",
          headers: {
            "X-Requested-With": "XMLHttpRequest"
          }
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
          if (result.errors) {
            markFieldErrors(demoForm, result.errors);
          }

          setStatus(result.message || "The request could not be submitted.", "error");
          return;
        }

        setStatus(result.message || "Request received.", "success");
        demoForm.reset();
      } catch (error) {
        setStatus("Network error. Check your connection and try again.", "error");
      } finally {
        if (submitButton) {
          submitButton.disabled = false;
        }
      }
    });
  }
})();
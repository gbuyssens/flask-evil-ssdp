(function () {
  "use strict";

  function init() {
    var uid = document.getElementById("uidInput");
    var uidError = document.getElementById("uidError");
    var identBtn = document.getElementById("identBtn");
    var chip = document.getElementById("userChip");
    var chipName = document.getElementById("chipName");
    var pw = document.getElementById("passwordInput");

    if (!uid || !identBtn) {
      return;
    }

    identBtn.addEventListener("click", function (event) {
      var value = uid.value.trim();
      if (!value) {
        event.preventDefault();
        if (uidError) {
          uidError.classList.add("show");
        }
        uid.focus();
        return;
      }
      if (uidError) {
        uidError.classList.remove("show");
      }
      if (chip && chipName) {
        chipName.textContent = value;
        chip.style.display = "flex";
      }
    });

    uid.addEventListener("input", function () {
      if (uidError) {
        uidError.classList.remove("show");
      }
    });

    window.addEventListener("hashchange", function () {
      if (window.location.hash === "#password" && pw) {
        pw.focus();
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

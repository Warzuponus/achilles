// The War Room's only script. It is served from this binary (no CDN, so the page
// works offline and nothing outside this machine can change what runs in it), and
// the Content-Security-Policy allows scripts from this origin only.
//
// Both behaviours are enhancements: without JavaScript the feedback form posts and
// shows the result page, and the project switcher has a submit button.
(function () {
  "use strict";

  // Project switcher: change the selection, load that project.
  document.addEventListener("change", function (ev) {
    var el = ev.target;
    if (el && el.matches && el.matches("select[data-autosubmit]") && el.form) {
      el.form.submit();
    }
  });

  // Feedback: post in place and show the outcome where the buttons were.
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!form || !form.matches || !form.matches("form[data-feedback]")) {
      return;
    }
    ev.preventDefault();
    var body = new URLSearchParams(new FormData(form));
    if (ev.submitter && ev.submitter.name) {
      body.set(ev.submitter.name, ev.submitter.value);
    }
    var note = document.createElement("div");
    note.className = "verdict";
    fetch(form.action, { method: "POST", body: body, credentials: "same-origin" })
      .then(function (res) {
        return res.text().then(function (text) {
          // The reply is plain text either way; it is never parsed as HTML.
          note.textContent = res.ok ? text : "not recorded: " + text.trim();
          if (res.ok) {
            form.replaceWith(note);
          } else {
            form.after(note);
          }
        });
      })
      .catch(function () {
        note.textContent = "not recorded: the War Room did not answer";
        form.after(note);
      });
  });
})();

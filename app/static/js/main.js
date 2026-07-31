// LinkLens frontend helpers. No build step, just plain JS.

(function () {
	"use strict";

	// ---------- index page: scan overlay ----------
	var form = document.getElementById("analyzeForm");
	if (form) {
		form.addEventListener("submit", function () {
			var urlInput = document.getElementById("url");
			var url = (urlInput.value || "").trim();
			if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
				return; // let the browser's native validation handle it
			}

			var overlay = document.getElementById("scanOverlay");
			var stepEl = document.getElementById("scanStep");
			var progressEl = document.getElementById("scanProgress");
			overlay.hidden = false;

			var steps = [
				"Checking the URL",
				"Opening a sandboxed browser",
				"Loading the page...",
				"Watching network activity",
				"Scanning downloads & content",
				"Asking the AI to weigh in",
				"Writing up the report",
			];
			var stepIndex = 0;
			var progress = 0;

			var stepTimer = setInterval(function () {
				if (stepIndex < steps.length - 1) {
					stepIndex += 1;
					stepEl.textContent = steps[stepIndex];
				}
				progress = Math.min(progress + 4, 92);
				progressEl.style.width = progress + "%";
			}, 1500);

			// The page will navigate once the server finishes. Keep the
			// overlay tidy if something goes wrong and we bounce back.
			window.addEventListener("pageshow", function (event) {
				if (event.persisted) clearInterval(stepTimer);
			});
			window.setTimeout(function () {
				// Safety valve: if we're somehow still here after 2 minutes,
				// stop the fake progress and let the user see the result.
				clearInterval(stepTimer);
			}, 120000);
		});
	}

	// ---------- result page: copy JSON ----------
	var copyBtn = document.getElementById("copyJsonBtn");
	if (copyBtn) {
		copyBtn.addEventListener("click", function () {
			var raw = document.getElementById("result-data").textContent;
			var pretty = JSON.stringify(JSON.parse(raw), null, 2);
			navigator.clipboard.writeText(pretty).then(function () {
				var toast = document.getElementById("copyToast");
				toast.hidden = false;
				setTimeout(function () { toast.hidden = true; }, 1800);
			});
		});
	}

	// ---------- result page: animate the gauge ----------
	var fill = document.querySelector(".gauge-fill");
	if (fill) {
		// The template renders the final dashoffset; we animate from full.
		var target = fill.getAttribute("stroke-dashoffset");
		fill.setAttribute("stroke-dashoffset", "439.8");
		requestAnimationFrame(function () {
			requestAnimationFrame(function () {
				fill.setAttribute("stroke-dashoffset", target);
			});
		});
	}
})();

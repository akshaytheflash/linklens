// LinkLens — frontend. No build step, just plain JS.
// Micro-interactions inspired by the dream2 design system.

(function () {
	"use strict";

	var prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

	// ---------- theme toggle ----------
	var themeToggle = document.getElementById("themeToggle");
	function applyTheme(theme) {
		document.documentElement.setAttribute("data-theme", theme);
	}
	function initTheme() {
		var stored = null;
		try { stored = localStorage.getItem("linklens-theme"); } catch (e) {}
		if (stored === "dark" || stored === "light") {
			applyTheme(stored);
		} else {
			applyTheme(
				window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
			);
		}
	}
	if (themeToggle) {
		themeToggle.addEventListener("click", function () {
			var current = document.documentElement.getAttribute("data-theme");
			var next = current === "dark" ? "light" : "dark";
			applyTheme(next);
			try { localStorage.setItem("linklens-theme", next); } catch (e) {}
		});
	}
	initTheme();

	// ---------- mouse glow ----------
	document.querySelectorAll(".mouse-glow").forEach(function (container) {
		var glow = container.querySelector(".glow");
		if (!glow) return;
		var raf = null;
		container.addEventListener("mousemove", function (e) {
			var rect = container.getBoundingClientRect();
			var x = e.clientX - rect.left;
			var y = e.clientY - rect.top;
			if (raf) cancelAnimationFrame(raf);
			raf = requestAnimationFrame(function () {
				glow.style.transform = "translate(" + x + "px," + y + "px) translate(-50%, -50%)";
			});
		});
	});

	// ---------- magnetic buttons ----------
	if (!prefersReducedMotion) {
		document.querySelectorAll(".magnetic").forEach(function (el) {
			var strength = parseFloat(el.getAttribute("data-strength") || "0.3");
			var raf = null;
			el.addEventListener("mousemove", function (e) {
				var rect = el.getBoundingClientRect();
				var dx = e.clientX - (rect.left + rect.width / 2);
				var dy = e.clientY - (rect.top + rect.height / 2);
				if (raf) cancelAnimationFrame(raf);
				raf = requestAnimationFrame(function () {
					el.style.transform = "translate(" + dx * strength + "px," + dy * strength + "px)";
				});
			});
			el.addEventListener("mouseleave", function () {
				if (raf) cancelAnimationFrame(raf);
				el.style.transition = "transform 0.45s cubic-bezier(0.16, 1, 0.3, 1)";
				el.style.transform = "translate(0,0)";
				setTimeout(function () { el.style.transition = ""; }, 450);
			});
		});
	}

	// ---------- card tilt ----------
	if (!prefersReducedMotion) {
		document.querySelectorAll(".tilt").forEach(function (el) {
			var raf = null;
			el.addEventListener("mousemove", function (e) {
				var rect = el.getBoundingClientRect();
				var px = (e.clientX - rect.left) / rect.width - 0.5;
				var py = (e.clientY - rect.top) / rect.height - 0.5;
				if (raf) cancelAnimationFrame(raf);
				raf = requestAnimationFrame(function () {
					el.style.transform =
						"perspective(900px) rotateX(" + (-py * 5).toFixed(2) + "deg) rotateY(" + (px * 5).toFixed(2) + "deg) translateY(-3px)";
				});
			});
			el.addEventListener("mouseleave", function () {
				if (raf) cancelAnimationFrame(raf);
				el.style.transition = "transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)";
				el.style.transform = "";
				setTimeout(function () { el.style.transition = ""; }, 500);
			});
		});
	}

	// ---------- scroll reveal ----------
	var revealEls = document.querySelectorAll(".reveal");
	if ("IntersectionObserver" in window && revealEls.length) {
		var io = new IntersectionObserver(function (entries) {
			entries.forEach(function (entry) {
				if (entry.isIntersecting) {
					entry.target.classList.add("in-view");
					io.unobserve(entry.target);
				}
			});
		}, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });
		revealEls.forEach(function (el) { io.observe(el); });
	} else {
		revealEls.forEach(function (el) { el.classList.add("in-view"); });
	}

	// ---------- animated counters ----------
	if (!prefersReducedMotion) {
		document.querySelectorAll(".count").forEach(function (el) {
			var target = parseFloat(el.getAttribute("data-count") || "0");
			var suffix = el.getAttribute("data-suffix") || "";
			var decimals = el.getAttribute("data-decimals") ? parseInt(el.getAttribute("data-decimals"), 10) : 0;
			var duration = 1100;
			var start = null;
			function tick(ts) {
				if (!start) start = ts;
				var p = Math.min((ts - start) / duration, 1);
				var eased = 1 - Math.pow(1 - p, 3);
				var value = target * eased;
				el.textContent = value.toFixed(decimals) + suffix;
				if (p < 1) requestAnimationFrame(tick);
			}
			var started = false;
			var cio = new IntersectionObserver(function (entries) {
				if (entries[0].isIntersecting && !started) {
					started = true;
					requestAnimationFrame(tick);
					cio.disconnect();
				}
			}, { threshold: 0.4 });
			cio.observe(el);
		});
	}

	// ---------- index page: scan overlay ----------
	var form = document.getElementById("analyzeForm");
	if (form) {
		form.addEventListener("submit", function (e) {
			var urlInput = document.getElementById("url");
			var url = (urlInput.value || "").trim();
			if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
				return; // native validation
			}

			var overlay = document.getElementById("scanOverlay");
			var stepsEl = document.getElementById("scanSteps");
			var progressEl = document.getElementById("scanProgress");
			var overlayUrl = document.getElementById("scanOverlayUrl");
			if (!overlay) return;

			overlayUrl.textContent = url;
			stepsEl.innerHTML = "";
			var steps = [
				"Checking the URL",
				"Opening a sandboxed browser",
				"Loading the page",
				"Watching network activity",
				"Scanning downloads and content",
				"Asking the AI to weigh in",
				"Writing up the report",
			];
			var stepEls = steps.map(function (label) {
				var li = document.createElement("div");
				li.className = "scan-step";
				li.innerHTML =
					'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>' +
					'<span class="st">' + label + "</span>";
				stepsEl.appendChild(li);
				return li;
			});

			overlay.classList.add("active");
			document.body.style.overflow = "hidden";

			var stepIndex = 0;
			var progress = 0;
			var stepTimer = setInterval(function () {
				if (stepIndex < stepEls.length - 1) {
					stepEls[stepIndex].classList.add("done");
					stepIndex += 1;
				}
				progress = Math.min(progress + 3, 90);
				progressEl.style.width = progress + "%";
			}, 1300);

			window.addEventListener("pageshow", function (event) {
				if (event.persisted) {
					clearInterval(stepTimer);
					overlay.classList.remove("active");
					document.body.style.overflow = "";
				}
			});
			window.setTimeout(function () { clearInterval(stepTimer); }, 120000);
		});
	}

	// ---------- result page: animated score ring ----------
	var ringValue = document.querySelector(".score-ring-value");
	if (ringValue) {
		var radius = parseFloat(ringValue.getAttribute("data-r"));
		var circumference = 2 * Math.PI * radius;
		var finalOffset = parseFloat(ringValue.getAttribute("stroke-dashoffset"));
		if (!prefersReducedMotion) {
			ringValue.style.strokeDashoffset = circumference;
			requestAnimationFrame(function () {
				requestAnimationFrame(function () {
					ringValue.style.strokeDashoffset = finalOffset;
				});
			});
		} else {
			ringValue.style.strokeDashoffset = finalOffset;
		}
	}

	// ---------- result page: count up the numeric score ----------
	var scoreNum = document.getElementById("scoreNum");
	if (scoreNum) {
		var scoreTarget = parseFloat(scoreNum.getAttribute("data-score") || "0");
		if (!prefersReducedMotion) {
			var scoreStart = null;
			function scoreTick(ts) {
				if (!scoreStart) scoreStart = ts;
				var p = Math.min((ts - scoreStart) / 1200, 1);
				var eased = 1 - Math.pow(1 - p, 3);
				scoreNum.textContent = (scoreTarget * eased).toFixed(1);
				if (p < 1) requestAnimationFrame(scoreTick);
			}
			requestAnimationFrame(scoreTick);
		} else {
			scoreNum.textContent = scoreTarget.toFixed(1);
		}
	}

	// ---------- result page: reveal breakdown bars ----------
	var breakFills = document.querySelectorAll(".break-fill");
	if ("IntersectionObserver" in window && breakFills.length) {
		var bio = new IntersectionObserver(function (entries) {
			entries.forEach(function (entry) {
				if (entry.isIntersecting) {
					var width = parseFloat(entry.target.getAttribute("data-width") || "0");
					entry.target.style.width = width + "%";
					bio.unobserve(entry.target);
				}
			});
		}, { threshold: 0.3 });
		breakFills.forEach(function (el) { bio.observe(el); });
	}

	// ---------- result page: copy JSON ----------
	var copyBtn = document.getElementById("copyJsonBtn");
	if (copyBtn) {
		copyBtn.addEventListener("click", function () {
			var raw = document.getElementById("result-data").textContent;
			var pretty = JSON.stringify(JSON.parse(raw), null, 2);
			navigator.clipboard.writeText(pretty).then(function () {
				var original = copyBtn.innerHTML;
				copyBtn.innerHTML =
					'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><polyline points="22 4 12 14 9 11"/></svg>' +
					"Copied";
				copyBtn.classList.add("btn-primary");
				setTimeout(function () {
					copyBtn.innerHTML = original;
					copyBtn.classList.remove("btn-primary");
				}, 1800);
			});
		});
	}
})();

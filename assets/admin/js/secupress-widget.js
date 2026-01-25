(function() {
	function initSecuPressCharts() {
		if (typeof Chart === "undefined") {
			setTimeout(initSecuPressCharts, 100);
			return;
		}
		
		var chartData = SecuPressi18nWidget.chartData;
		var chartsInitialized = 0;
		
		// Detect Chart.js version (2.x+ has Chart.version property)
		var isModernChart = Chart && Chart.hasOwnProperty('version');

		function tryInitChart(chart) {
			var canvas = document.getElementById(chart.id);
			if (!canvas) {
				return false;
			}
			// Check if canvas is visible and has dimensions
			var rect = canvas.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) {
				return false;
			}
			// Ensure canvas has explicit dimensions
			if (!canvas.width || !canvas.height) {
				canvas.width = canvas.offsetWidth || 200;
				canvas.height = canvas.offsetHeight || 120;
			}
			var ctx = canvas.getContext("2d");
			if (!ctx) {
				return false;
			}
			try {
				if (isModernChart) {
					// Chart.js 2.x+ syntax
					new Chart(ctx, {
						type: 'line',
						data: {
							labels: chart.labels,
							datasets: [{
								fill: true,
								backgroundColor: "rgba(220,50,50,0.1)",
								borderColor: "#dc3232",
								pointBackgroundColor: "#dc3232",
								pointBorderColor: "#fff",
								pointHoverBackgroundColor: "#fff",
								pointHoverBorderColor: "#dc3232",
								data: chart.data,
								tension: 0.4
							}]
						},
						options: {
							responsive: true,
							maintainAspectRatio: false,
							plugins: {
								legend: {
									display: false
								},
								tooltip: {
									enabled: true
								}
							},
							scales: {
								x: {
									display: false
								},
								y: {
									display: false
								}
							},
							elements: {
								point: {
									radius: 3
								},
								line: {
									borderWidth: 2
								}
							}
						}
					});
				} else {
					// Chart.js 1.x syntax
					new Chart(ctx).Line({
						labels: chart.labels,
						datasets: [{
							fillColor: "rgba(220,50,50,0.1)",
							strokeColor: "#dc3232",
							pointColor: "#dc3232",
							pointStrokeColor: "#fff",
							pointHighlightFill: "#fff",
							pointHighlightStroke: "#dc3232",
							data: chart.data
						}]
					}, {
						responsive: true,
						maintainAspectRatio: false,
						showScale: false,
						showTooltips: true,
						pointDot: true,
						pointDotRadius: 3,
						datasetStroke: true,
						datasetStrokeWidth: 2,
						datasetFill: true,
						bezierCurve: true,
						bezierCurveTension: 0.4,
						scaleShowLabels: false,
						scaleShowGridLines: false,
						scaleShowHorizontalLines: false,
						scaleShowVerticalLines: false,
						legend: false
					});
				}
				return true;
			}
			catch (e) {
				console.error("SecuPress chart error for " + chart.id + ":", e);
				return false;
			}
		}
		
		for (var i = 0; i < chartData.length; i++) {
			if (tryInitChart(chartData[i])) {
				chartsInitialized++;
			}
		}
		
		// Retry for charts that failed to initialize (might not be visible yet)
		if (chartsInitialized < chartData.length) {
			setTimeout(function() {
				for (var i = 0; i < chartData.length; i++) {
					var canvas = document.getElementById(chartData[i].id);
					if (canvas && !canvas.chartInitialized) {
						if (tryInitChart(chartData[i])) {
							canvas.chartInitialized = true;
						}
					}
				}
			}, 500);
		}
	}

	function startInit() {
		if (document.readyState === "loading") {
			document.addEventListener("DOMContentLoaded", function() {
				setTimeout(initSecuPressCharts, 100);
			});
		} else {
			jQuery(document).ready(function() {
				setTimeout(initSecuPressCharts, 100);
			});
		}
	}
	
	startInit();
})();
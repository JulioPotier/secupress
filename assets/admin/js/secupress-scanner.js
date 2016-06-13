/* globals jQuery: false, ajaxurl: false, SecuPressi18nScanner: false, SecuPressi18nChart: false, secupressIsSpaceOrEnterKey: false, Chart: false, swal2: false */
// Global vars =====================================================================================
var SecuPress = {
	supportButtonColor:  "#F1C40F",
	swal2Defaults:        {
		confirmButtonText: SecuPressi18nScanner.confirmText,
		cancelButtonText:  SecuPressi18nScanner.cancelText,
		type:              "warning",
		allowOutsideClick: true,
		customClass:       "wpmedia-swal2 secupress-swal2"
	},
	swal2ConfirmDefaults: {
		showCancelButton:  true,
		closeOnConfirm:    false
	}
};


jQuery( document ).ready( function( $ ) {
	var secupressChart = {},
		secupressChartEls = [],
		secupressOneClickScanProgress = 0;

	if ( document.getElementById( 'status_chart' ) ) {
		secupressChartEls.push( document.getElementById( 'status_chart' ) );
	}

	if ( document.getElementById( 'status_chart_mini' ) ) {
		secupressChartEls.push( document.getElementById( 'status_chart_mini' ) );
	}


	// !Big network: set some data. ================================================================
	( function( w, d, $, undefined ) {
		function secupressSetBigData( href, $button, $spinner, $percent ) {
			$.getJSON( href )
			.done( function( r ) {
				if ( ! r.success ) {
					$spinner.replaceWith( '<span class="secupress-error-notif">' + SecuPressi18nScanner.error + "</span>" );
					$percent.remove();
					return;
				}
				if ( r.data ) {
					$percent.text( r.data + "%" );

					if ( 100 !== r.data ) {
						// We need more data.
						secupressSetBigData( href, $button, $spinner, $percent );
						return;
					}
				}
				// Finish.
				$button.closest( ".secupress-notice" ).fadeTo( 100 , 0, function() {
					$( this ).slideUp( 100, function() {
						$( this ).remove();
					} );
				} );
			} )
			.fail( function() {
				$spinner.replaceWith( '<span class="secupress-error-notif">' + SecuPressi18nScanner.error + "</span>" );
				$percent.remove();
			} );
		}


		$( ".secupress-centralize-blog-options" ).on( "click.secupress keyup", function( e ) {
			var $this, href, $spinner, $percent;

			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			$this    = $( this );
			href     = $this.attr( "href" ).replace( "admin-post.php", "admin-ajax.php" );
			$spinner = $( '<img src="' + SecuPressi18nScanner.spinnerUrl + '" alt="" class="secupress-spinner" />' );
			$percent = $( '<span class="secupress-ajax-percent">0%</span>' );

			if ( $this.hasClass( "running" ) ) {
				return false;
			}

			$this.addClass( "running" ).parent().append( $spinner ).append( $percent ).find( ".secupress-error-notif" ).remove();

			e.preventDefault();

			secupressSetBigData( href, $this, $spinner, $percent );
		} );
	} )( window, document, $ );


	// !Chart and score ============================================================================
	function secupressDrawCharts() {
		var chartData;

		if ( ! secupressChartEls || ! window.Chart || ! SecuPressi18nChart ) {
			return;
		}

		if ( $.isEmptyObject( secupressChart ) ) {
			// The charts are not created yet.
			chartData = [
				{
					value:     SecuPressi18nChart.good.value,
					color:     "#26B3A9",
					highlight: "#2BCDC1",
					label:     SecuPressi18nChart.good.text,
					status:    "good",
				},
				{
					value:     SecuPressi18nChart.bad.value,
					color:     "#CB234F",
					highlight: "#F2295E",
					label:     SecuPressi18nChart.bad.text,
					status:    "bad",
				},
				{
					value:     SecuPressi18nChart.warning.value,
					color:     "#F7AB13",
					highlight: "#F1C40F",
					label:     SecuPressi18nChart.warning.text,
					status:    "warning",
				}
			];

			if ( SecuPressi18nChart.notscannedyet.value ) {
				chartData.push( {
					value:     SecuPressi18nChart.notscannedyet.value,
					color:     "#5A626F",
					highlight: "#888888",
					label:     SecuPressi18nChart.notscannedyet.text,
					status:    "notscannedyet",
				} );
			}

			$.each( secupressChartEls, function( i, chartEl ) {
				var elID = chartEl.id;

				secupressChart[ elID ] = new Chart( chartEl.getContext( "2d" ) ).Doughnut( chartData, {
					animationEasing:       "easeInOutQuart",
					showTooltips:          true,
					segmentShowStroke:     false,
					percentageInnerCutout: 90,
					tooltipEvents:         ["mousemove"], // active "hover" effect...
					customTooltips:        function() {} //... but remove tooltips.
				} );

				// Trigger a filter action on Chart Segment click.
				chartEl.onclick = function( e ) {
					var activePoints = secupressChart[ elID ].getSegmentsAtEvent( e );
					if ( activePoints[0] ) {
						$( "#secupress-type-filters" ).find( ".secupress-big-tab-" + activePoints[0].status ).find( "a" ).trigger( "click.secupress" );
					}
				};
			} );
		} else {
			// Update existing charts.
			$.each( secupressChartEls, function( i, chartEl ) {
				var elID = chartEl.id;

				secupressChart[ elID ].segments[0].value = SecuPressi18nChart.good.value;
				secupressChart[ elID ].segments[1].value = SecuPressi18nChart.bad.value;
				secupressChart[ elID ].segments[2].value = SecuPressi18nChart.warning.value;

				if ( typeof secupressChart[ elID ].segments[3] !== 'undefined' ) {
					secupressChart[ elID ].segments[3].value = SecuPressi18nChart.notscannedyet.value;
				}

				secupressChart[ elID ].update();
			} );
		}

		if ( ! SecuPressi18nChart.notscannedyet.value ) {
			// Remove the legend for "Not scanned yet".
			$( ".secupress-chart-legend .status-notscannedyet" ).remove();
		}
	}


	function secupressSelectFallbackBigTab( data, $filters ) {
		if ( data.bad ) {
			$filters.find( ".secupress-big-tab-bad a" ).trigger( "click.secupress" );
		} else if ( data.warning ) {
			$filters.find( ".secupress-big-tab-warning a" ).trigger( "click.secupress" );
		} else if ( data.good ) {
			$filters.find( ".secupress-big-tab-good a" ).trigger( "click.secupress" );
		}
	}


	/**
	 * Disable one or more buttons.
	 * - Add a "aria-disabled" attribute.
	 * - If it's a link: add a "disabled" attribute. If it's a button or input: add a "disabled" attribute.
	 *
	 * @since 1.0
	 *
	 * @param (object) $buttons jQuery object of one or more buttons.
	 */
	function secupressDisableButtons( $buttons ) {
		$buttons.each( function() {
			var $button  = $( this ),
				nodeName = this.nodeName.toLowerCase();

			if ( "button" === nodeName || "input" === nodeName ) {
				$button.attr( { "disabled": "disabled", "aria-disabled": "true" } );
			} else {
				$button.addClass( "disabled" ).attr( "aria-disabled", "true" );
			}
		} );
	}


	/**
	 * Enable one or more buttons.
	 * - Remove the "aria-disabled" attribute.
	 * - If it's a link: remove the "disabled" attribute. If it's a button or input: remove the "disabled" attribute.
	 *
	 * @since 1.0
	 *
	 * @param (object) $buttons jQuery object of one or more buttons.
	 */
	function secupressEnableButtons( $buttons ) {
		$buttons.each( function() {
			var $button  = $( this ),
				nodeName = this.nodeName.toLowerCase();

			if ( "button" === nodeName || "input" === nodeName ) {
				$button.removeAttr( "disabled aria-disabled" );
			} else {
				$button.removeClass( "disabled" ).removeAttr( "aria-disabled" );
			}
		} );
	}


	/**
	 * Tell if a button is disabled.
	 *
	 * @since 1.0
	 *
	 * @param (object) $button jQuery object of the button.
	 *
	 * @return (bool)
	 */
	function secupressIsButtonDisabled( $button ) {
		var nodeName = $button.get( 0 ).nodeName.toLowerCase();

		if ( "button" === nodeName || "input" === nodeName ) {
			return $button.prop( "disabled" );
		}

		$button.hasClass( "disabled" );
	}


	// Print counters in the page.
	function secupressPrintScore( data ) {
		var $filters;

		if ( ! secupressChartEls || ! window.Chart ) {
			return;
		}

		// All various texts.
		$( ".secupress-chart-container .letter" ).replaceWith( data.letter );
		$( ".secupress-score-text" ).text( data.text );
		$( ".secupress-scan-infos .secupress-score" ).html( data.subtext );
		$( "#wp-admin-bar-secupress" ).find( ".letter" ).text( data.grade );
		$( "#toplevel_page_" + SecuPressi18nScanner.pluginSlug + "_scanners" ).find( ".update-count" ).text( data.bad ).parent().attr( "class", function( i, val ) {
			return val.replace( /count-\d+/, "count-" + data.bad );
		} );

		// Charts.
		if ( SecuPressi18nChart ) {
			SecuPressi18nChart.good.value          = data.good;
			SecuPressi18nChart.bad.value           = data.bad;
			SecuPressi18nChart.warning.value       = data.warning;
			SecuPressi18nChart.notscannedyet.value = data.notscannedyet;

			secupressDrawCharts();
		}

		// Tabs subtitles.
		$filters = $( "#secupress-type-filters" );

		$filters.find( "a" ).each( function() {
			var $this = $( this ),
				type  = $this.data( "type" );
			$this.children( ".secupress-tab-subtitle" ).text( data[ type + "-text" ] );
		} );

		// Show/Hide the "New" tab.
		if ( ! data.notscannedyet ) {
			if ( $filters.children( ".secupress-big-tab-notscannedyet" ).children( "a" ).hasClass( "secupress-current" ) ) {
				secupressSelectFallbackBigTab( data, $filters );
			}

			$filters.children( ".secupress-big-tab-notscannedyet" ).remove();
		} else {
			$( ".secupress-count-notscannedyet" ).text( data.notscannedyet );
		}

		// Show/Hide the "Action needed" tab.
		if ( data.hasaction ) {
			$filters.children( ".secupress-big-tab-hasaction" ).removeClass( "hidden" ).removeAttr( "aria-hidden" );
			// Switch to this tab only if it's a bulk action.
			if ( data.isBulk ) {
				$filters.find( ".secupress-big-tab-hasaction a" ).trigger( "click.secupress" );
			}
		} else {
			if ( $filters.children( ".secupress-big-tab-hasaction" ).children( "a" ).hasClass( "secupress-current" ) ) {
				secupressSelectFallbackBigTab( data, $filters );
			}

			$filters.children( ".secupress-big-tab-hasaction" ).addClass( "hidden" ).attr( "aria-hidden", true );
		}

		// Twitter.
		if ( "A" === data.grade ) {
			$( "#tweeterA" ).slideDown();
		} else {
			$( "#tweeterA" ).slideUp();
		}
	}

	// Get counters and print them in the page.
	function secupressPrintScoreFromAjax( isBulk ) {
		var params;

		if ( ! SecuPressi18nScanner.i18nNonce ) {
			return;
		}

		params = {
			"action":   "secupress-get-scan-counters",
			"_wpnonce": SecuPressi18nScanner.i18nNonce
		};

		$.getJSON( ajaxurl, params )
		.done( function( r ) {
			if ( $.isPlainObject( r ) && r.success && r.data ) {
				r.data.isBulk = isBulk;
				secupressPrintScore( r.data );
			}
		} );
	}


	// If it's not the first scan, draw the charts.
	if ( secupressChartEls && window.Chart ) {
		if ( ! $( '.secupress-scanners-header' ).hasClass( 'secupress-not-scanned-yet' ) ) {
			secupressDrawCharts();
		}

		// Trigger a filter action on Legend item click.
		$( ".secupress-chart-legend" ).find( "li" ).on( "click.secupress", function() {
			$( "#secupress-type-filters" ).find( ".secupress-big-tab-" + $( this ).data( "status" ) ).find( "a" ).trigger( "click.secupress" );
		} );
	}


	// !Other UI. ==================================================================================
	// Filter rows (Status bad/good/etc).
	( function( w, d, $, undefined ) {
		$( "#secupress-type-filters" ).find( "a" ).on( "click.secupress keyup", function( e ) {
			var $this, priority, current = "active";

			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			$this = $( this );

			if ( $this.hasClass( current ) ) {
				return false;
			}

			priority = $this.data( "type" );

			$this.closest( "ul" ).find( "a" ).removeClass( current );
			$this.addClass( current );

			$( ".status-all" ).addClass( "hidden" ).attr( "aria-hidden", true ).filter( ".status-" + priority ).removeClass( "hidden" ).attr( "aria-hidden", false );
		} ).filter( ".secupress-current" ).trigger( "click.secupress" );
	} )( window, document, $ );


	// Filter Rows (Priority).
	( function( w, d, $, undefined ) {
		$( "#secupress-priority-filters" ).find( "input" ).on( "change.secupress", function( e ) {
			var $this    = $( this ),
				priority = $this.attr( "name" );

			if ( $this.is( ":checked" ) ) {
				$( ".secupress-table-prio-" + priority ).spFadeIn();
			} else {
				$( ".secupress-table-prio-" + priority ).spHide();
			}
			return false;
		} );
	} )( window, document, $ );


	// Ask for support button (free).
	( function( w, d, $, undefined ) {
		$( ".secupress-ask-support-free" ).on( "click.secupress keyup", function( e ) {
			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			e.preventDefault();

			swal2( $.extend( {}, SecuPress.swal2Defaults, SecuPress.swal2ConfirmDefaults, {
				title:              SecuPressi18nScanner.supportTitle,
				confirmButtonText:  SecuPressi18nScanner.supportButton,
				html:               SecuPressi18nScanner.supportContentFree,
				confirmButtonColor: SecuPress.supportButtonColor,
				type:               "question"
			} ) ).then( function( isConfirm ) {
				if ( true === isConfirm ) {
					swal2( $.extend( {}, SecuPress.swal2Defaults, {
						title:              "Pro Version needed", //// TODO: localize.
						type:               "error",
						showCancelButton:   true,
						confirmButtonText:  "Get Pro now!", //// TODO: localize.
						confirmButtonColor: SecuPress.supportButtonColor,
						reverseButtons:     true
					} ) );
				}
			} );
		} );
	} )( window, document, $ );


	// Ask for support button (pro).
	( function( w, d, $, undefined ) {
		$( ".secupress-ask-support-pro" ).on( "click.secupress keyup", function( e ) {
			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			e.preventDefault();

			swal2( $.extend( {}, SecuPress.swal2Defaults, SecuPress.swal2ConfirmDefaults, {
				title:              SecuPressi18nScanner.supportTitle,
				confirmButtonText:  SecuPressi18nScanner.supportButton,
				html:               SecuPressi18nScanner.supportContentPro,
				confirmButtonColor: SecuPress.supportButtonColor,
				type:               "question"
			} ) ).then( function( isConfirm ) {
				if ( true === isConfirm ) {
					swal2.enableLoading();

					$.post( ajaxurl, {}, null, "json" )
					.done( function( r ) {
						// Display fix re
					} )
					.fail( function() {
						// Error
					} );
				}
			} );
		} );
	} )( window, document, $ );


	// !Scans and fixes ============================================================================
	( function( w, d, $, undefined ) {
		var secupressScans = {
			// Scans.
			doingScan:    {},
			// Fixes.
			doingFix:     {},
			delayedFixes: [],
			// Manual fixes.
			manualFix:    {}
		};


		// Complete the slideshow
		function secupressAddCaroupoivrePagination() {
			$( '.secupress-caroupoivre' ).each( function() {
				var $this = $(this),
					i, nb_slides, pagination;

				if ( $this.next( '.secupress-caroupoivre-pagination' ).length !== 0 ) {
					return true;
				}

				nb_slides  = $this.find( '.secupress-slide[id]' ).length;
				pagination =  '<div class="secupress-caroupoivre-pagination">';

				for ( i = 0; i < nb_slides; i++ ) {
					pagination += '<span class="secupress-dot"></span>';
				}

				pagination += '</div>';
				$this.after( pagination );
			} );
		}

		secupressAddCaroupoivrePagination();


		// Runs the Progressbar, 10 sec min.
		function secupressRunProgressBar( $button ) {
			var $sp_scanning = $( '.secupress-one-click-scanning-slideshow' ),
				$sp_poivre   = $( '.secupress-caroupoivre' ),
				$pagination  = $( '.secupress-caroupoivre-pagination' ).find( '.secupress-dot' ),
				isFirst      = $button.closest( '.secupress-not-scanned-yet' ).length,
				$random_slide, secupressProgressTimer;

			// If first of the first one click scan.
			if ( isFirst ) {
				// Information about first scan & show progress + slides.
				$( '.secupress-before-caroupoivre' ).fadeOut( 200, function() {
					$sp_scanning.fadeIn( 200 );
				} );
			} else {
				$( '.secupress-tabs-contents' ).hide();
				$sp_scanning.fadeIn( 200 );
			}

			$sp_poivre.find( '.secupress-slide' ).hide();
			$random_slide = $( '.secupress-slide-' + Math.floor( ( Math.random() * 2 ) + 1 ) ).html();
			$sp_poivre.find( '#secupress-slide1' ).html( $random_slide );

			secupressProgressTimer = setInterval( function() {
				secupressOneClickScanProgress++;

				if ( secupressOneClickScanProgress >= 55 ) {
					if ( ! $sp_poivre.find( '#secupress-slide2' ).is( ":visible" ) ) {
						$sp_poivre.find( '#secupress-slide1' ).hide();
						$sp_poivre.find( '#secupress-slide2' ).fadeIn( 275 );
						$pagination.removeClass( 'current' ).eq( 1 ).addClass( 'current' );
					}
				} else if ( secupressOneClickScanProgress >= 0 ) {
					$sp_poivre.find( '#secupress-slide1' ).fadeIn( 275 );
					$pagination.removeClass( 'current' ).eq( 0 ).addClass( 'current' );
				}

				// We are between 9 & 10s but SP still doing scan, stay at 90%.
				// Windows counting style!
				if ( ! $.isEmptyObject( secupressScans.doingScan ) && secupressOneClickScanProgress > 90 && secupressOneClickScanProgress < 100 ) {
					secupressOneClickScanProgress = 90;
					return;
				}

				secupressOneClickScanProgress = Math.min( secupressOneClickScanProgress, 100 );

				$( '.secupress-progressbar' )
					.find( '.secupress-progressbar-val' ).css( 'width', secupressOneClickScanProgress + '%' )
					.find( '.secupress-progress-val-txt' ).text( secupressOneClickScanProgress + ' %' );

				if ( secupressOneClickScanProgress >= 100 ) {

					secupressOneClickScanProgress = 0;
					clearInterval( secupressProgressTimer );

					// makes slideshow desappear
					$sp_scanning.fadeOut( 200, function() {

						// Show other element (list of scans, tabs, tabs contents).
						$( '.secupress-scanners-header.secupress-not-scanned-yet' ).removeClass( 'secupress-not-scanned-yet' );

						// Explicitly show tabs content in case of other One Click Scans.
						$( '.secupress-tabs-contents' ).show();

						// Click on first tab to show results, just in case…
						$( '#secupress-l-scan' ).trigger( 'click.secupress' );

						// draw the chart
						if ( isFirst ) {
							secupressDrawCharts();
						}
					} );
				}
			}, 100 );
		}


		// Get test name from an URL.
		function secupressGetTestFromUrl( href ) {
			var test = href.match( /[&?]test=([^&]+)(?:$|&)/ );
			return test ? test[1] : false;
		}


		// Tell if a test is fixable.
		function secupressIsFixable( $row ) {
			return $row.hasClass( "status-bad" ) && ! $row.hasClass( "not-fixable" );
		}


		// Get current scan/fix status.
		function secupressGetCurrentStatus( $el ) {
			var classes, status = false;

			classes = $el.attr( "class" ).replace( /(\s|^)(status-error|status-all|status-hasaction)(\s|$)/g, " " ).replace( /^\s+|\s+$/g, "" ).replace( /\s+/, " " ).split( " " );

			$.each( classes, function( i, cl ) {
				if ( 0 === cl.indexOf( "status-" ) ) {
					status = cl.substr( 7 );
					return false;
				}
			} );

			return status;
		}


		// Set the scan/fix status class.
		function secupressSetStatusClass( $el, status ) {
			$el.removeClass( "status-error status-good status-bad status-warning status-notscannedyet status-cantfix" ).addClass( "status-" + status );
		}


		// Scan icon + status text.
		function secupressAddScanStatusText( $row, statusText ) {
			$row.find( ".secupress-status-text" ).html( statusText );
		}


		// Add a scan result.
		function secupressAddScanResult( $row, message ) {
			message = message ? SecuPressi18nScanner.scanResultLabel + message : '';
			$row.find( ".secupress-scan-message" ).html( message );
		}


		// Replace a scan status with an error icon + message.
		function secupressDisplayScanError( $row ) {
			var status = '<span class="dashicons dashicons-no secupress-dashicon" aria-hidden="true"></span> ' + SecuPressi18nScanner.error;

			// Add the icon + text.
			secupressAddScanStatusText( $row, status );

			// Empty the scan results.
			secupressAddScanResult( $row, "" );

			// Add a "status-error" class to the row.
			$row.addClass( "status-error" );

			return false;
		}


		// Fix icon + status text.
		function secupressAddFixStatusText( $row, statusText ) {
			$row.find( ".secupress-fix-status-text" ).html( statusText );
		}


		// Add a fix result.
		function secupressAddFixResult( $row, message ) {
			message = message ? SecuPressi18nScanner.fixResultLabel + message : '';
			$row.find( ".secupress-fix-result-message" ).html( message );
		}


		// Error popup.
		function secupressErrorWarn() {
			swal2( $.extend( {}, SecuPress.swal2Defaults, {
				title: SecuPressi18nScanner.error,
				type:  "error"
			} ) );
		}


		// Replace a fix status with an error icon + message.
		function secupressDisplayFixError( $row, warn ) {
			var statusText = '<span class="dashicons dashicons-no secupress-dashicon" aria-hidden="true"></span> ' + SecuPressi18nScanner.error;

			// Add the icon + text.
			secupressAddFixStatusText( $row, statusText );

			// Empty the fix results.
			secupressAddFixResult( $row, "" );

			// Add a "status-error" class to the td.
			$row.find( ".secupress-fix-result" ).addClass( "status-error" );

			if ( warn ) {
				secupressErrorWarn();
			}

			return false;
		}

		// Tell if the returned data (from a scan) has required infos.
		function secupressScanResponseHasRequiredData( r, $row ) {
			// Fail, or there's a problem with the returned data.
			if ( ! r.success || ! $.isPlainObject( r.data ) ) {
				return secupressDisplayScanError( $row );
			}

			// The data is incomplete.
			if ( ! r.data.status || ! r.data.class || ! r.data.message ) {
				return secupressDisplayScanError( $row );
			}

			return true;
		}


		// Tell if the returned data (from fix) has required infos.
		function secupressFixResponseHasRequiredData( r, $row, warn ) {
			warn = undefined === warn ? false : warn;

			// Fail, or there's a problem with the returned data.
			if ( ! r.success || ! $.isPlainObject( r.data ) ) {
				return secupressDisplayFixError( $row, warn );
			}

			// The data is incomplete.
			if ( ! r.data.class || ! r.data.message ) {
				return secupressDisplayFixError( $row, warn );
			}

			return true;
		}


		// Deal with scan infos.
		function secupressDisplayScanResult( r, test ) {
			var $row = $( "#" + test ),
				oldStatus;

			// Fail, or there's a problem with the returned data.
			if ( ! secupressScanResponseHasRequiredData( r, $row ) ) {
				return false;
			}

			// Get current status.
			oldStatus = secupressGetCurrentStatus( $row );

			// Add the new status as a class.
			secupressSetStatusClass( $row, r.data.class );

			// Add status.
			secupressAddScanStatusText( $row, r.data.status );

			// Add scan results.
			secupressAddScanResult( $row, r.data.message );

			return true;
		}


		// Tell if we need a manual fix.
		function secupressManualFixNeeded( data ) {
			return data.form_contents && data.form_fields || data.manualFix;
		}


		// Deal with fix infos.
		function secupressDisplayFixResult( r, test, warn ) {
			var $row = $( "#" + test ),
				$fix  = $row.find( ".secupress-fix-result" );

			warn = undefined === warn ? false : warn;

			// Fail, or there's a problem with the returned data.
			if ( ! secupressFixResponseHasRequiredData( r, $row, warn ) ) {
				return false;
			}

			// Add the new status as a class.
			//secupressSetStatusClass( $fix, r.data.class );

			// Add a specific class to the row if the fix needs the user intervention.
			if ( secupressManualFixNeeded( r.data ) ) {
				$row.addClass( "status-hasaction" );
			} else {
				$row.removeClass( "status-hasaction" );
			}

			// Add status.
			secupressAddFixStatusText( $row, r.data.status );

			// Add fix results.
			secupressAddFixResult( $row, r.data.message );

			return true;
		}


		// Tell there is no scans or fixes running.
		function secupressScansIsIdle() {
			return $.isEmptyObject( secupressScans.doingScan ) && $.isEmptyObject( secupressScans.doingFix ) && ! secupressScans.delayedFixes.length;
		}


		// Update the date of the last One Click Scan.
		function secupressUpdateDate( data ) {
			var $scoreResultsUl = $( "#secupress-latest" ).find( ".secupress-reports-list" );

			$scoreResultsUl.children( ".secupress-empty" ).remove();

			if ( $scoreResultsUl.children( "li" ).length === 5 ) {
				$scoreResultsUl.children( "li:last" ).slideUp( 250, function() {
					$( this ).remove();
					$scoreResultsUl.prepend( data ).find( "li.hidden" ).slideDown( 250 );
				} );
			} else {
				$scoreResultsUl.prepend( data ).find( "li.hidden" ).slideDown( 250 );
			}
		}


		function secupressScanEnd( isBulk ) {
			if ( secupressScansIsIdle() ) {
				$( "body" ).trigger( "allScanDone.secupress", [ { isBulk: isBulk } ] );
			}
		}


		// Perform a scan: spinner + row class + ajax call + display result.
		function secupressScanit( test, $row, href, isBulk ) {
			if ( ! test ) {
				// Something's wrong here.
				secupressDisplayScanError( $row ); // TOCHECK
				return secupressScanEnd( isBulk );
			}

			if ( secupressScans.doingScan[ test ] ) {
				// Oy! Slow down!
				return;
			}

			// Show our scan is running.
			secupressScans.doingScan[ test ] = 1;
			$row.addClass( "scanning" ).removeClass( "status-error" );

			// Ajax call
			$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ) )
			.done( function( r ) {
				// Display scan result.
				if ( secupressDisplayScanResult( r, test ) ) {
					delete secupressScans.doingScan[ test ];

					// If it's an auto-scan and the result is good, remove the fix status.
					if ( $row.hasClass( "autoscan" ) ) {
						$row.removeClass( "autoscan" );

						if ( "good" === r.data.class ) {
							$row.find( ".secupress-fix-result" ).html( "" );
						}
					}

					// Trigger an event.
					$( "body" ).trigger( "scanDone.secupress", [ {
						test:   test,
						href:   href,
						isBulk: isBulk,
						data:   r.data
					} ] );

				} else {
					delete secupressScans.doingScan[ test ];
				}
			} )
			.fail( function() {
				delete secupressScans.doingScan[ test ];

				// Error
				secupressDisplayScanError( $row );
			} )
			.always( function() {
				// Show our scan is completed.
				$row.removeClass( "scanning" );

				secupressScanEnd( isBulk );
			} );
		}


		function secupressFixEnd( isBulk ) {
			if ( $.isEmptyObject( secupressScans.doingFix ) && ! secupressScans.delayedFixes.length ) {
				// No fixes are running and no delayed fixes left in queue. This is the last fix!
				if ( isBulk ) {
					// Enable fix buttons again, only when all fixes are done.
					$( ".secupress-fixit" ).removeClass( "disabled" );
				}
				// Finally, trigger an event.
				$( "body" ).trigger( "allFixDone.secupress", [ { isBulk: isBulk } ] );
			}
		}


		// Perform a fix: spinner + row class + ajax call + display result + set the prop `secupressScans.manualFix` if a manual fix is needed.
		function secupressFixit( test, $row, href, isBulk ) {
			var $button;

			if ( ! test ) {
				// Something's wrong here.
				secupressDisplayFixError( $row, ! isBulk );
				return secupressFixEnd( isBulk );
			}

			if ( secupressScans.doingFix[ test ] ) {
				// Oy! Slow down!
				return;
			}

			if ( ! isBulk && ! $.isEmptyObject( secupressScans.doingFix ) ) {
				// One fix at a time if no bulk.
				return false;
			}

			if ( ! secupressIsFixable( $row ) ) {
				// Not fixable.
				return secupressFixEnd( isBulk );
			}

			$( ".secupress-fixit" ).addClass( "disabled" );

			// Show our fix is running.
			secupressScans.doingFix[ test ] = 1;
			$row.addClass( "fixing" ).removeClass( "status-error" );

			// Ajax call
			$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ) )
			.done( function( r ) {
				// Display fix result.
				if ( secupressDisplayFixResult( r, test, ! isBulk ) ) {

					delete secupressScans.doingFix[ test ];

					// If we need a manual fix, store the info.
					if ( secupressManualFixNeeded( r.data ) ) {
						secupressScans.manualFix[ test ] = r.data;
					}

					// Trigger an event.
					$( "body" ).trigger( "fixDone.secupress", [ {
						test:      test,
						href:      href,
						isBulk:    isBulk,
						manualFix: secupressManualFixNeeded( r.data ),
						data:      r.data
					} ] );
				} else {
					delete secupressScans.doingFix[ test ];
				}
			} )
			.fail( function() {
				delete secupressScans.doingFix[ test ];

				// Error.
				secupressDisplayFixError( $row, ! isBulk );
			} )
			.always( function() {
				// Show our fix is completed.
				$row.removeClass( "fixing" );

				// Enable fix buttons again.
				if ( ! isBulk ) {
					$( ".secupress-fixit" ).removeClass( "disabled" );
				}

				secupressFixEnd( isBulk );
			} );
		}


		function secupressFixFirstQueued( isBulk ) {
			var bulk = isBulk ? "bulk" : "",
				elem = secupressScans.delayedFixes.shift();
			$( elem ).trigger( bulk + "fix.secupress" );
		}


		function secupressFilterNonDelayedButtons( $buttons ) {
			// If we're already performing a fix, do nothing.
			if ( ! $.isEmptyObject( secupressScans.doingFix ) ) {
				return $buttons;
			}
			// Some fixes may need to be queued and delayed.
			$buttons.filter( ".delayed-fix" ).each( function() {
				secupressScans.delayedFixes.push( this );
			} );
			return $buttons.not( ".delayed-fix" );
		}


		function secupressLaunchSeparatedBulkFix( $buttons ) {
			if ( $buttons.length < 2 ) {
				// Not a bulk.
				$buttons.trigger( "fix.secupress" );
				return;
			}

			$buttons = secupressFilterNonDelayedButtons( $buttons );

			if ( $buttons.length ) {
				// We still have "normal" fixes.
				$buttons.trigger( "bulkfix.secupress" );
			} else {
				// OK, launch directly the fix of the first item in queue.
				secupressFixFirstQueued( true );
			}
		}


		// Perform a manual fix: display the form in a popup and launch an ajax call on submit.
		function secupressManualFixit( test ) {
			var content  = "",
				swal2Type = "info",
				index, data;

			data = secupressScans.manualFix[ test ];
			delete secupressScans.manualFix[ test ];

			data.message = data.message.replace( /(<ul>|<li>|<\/li><\/ul>)/g, '' ).replace( /<\/li>/g, "<br/>" );

			// If the status is "bad" or "warning", `data.message` contains an error message.
			if ( "bad" === data.class || "warning" === data.class ) {
				content += '<div class="sa-error-container show"><div class="icon">!</div><p>' + data.message + "</p></div>";
				swal2Type = "bad" === data.class ? "error" : "warning";
			}

			content += '<form method="post" id="form_manual_fix" class="secupress-swal2-form show-input" action="' + ajaxurl + '">';

				for ( index in data.form_contents ) {
					if ( data.form_contents.hasOwnProperty( index ) ) {
						content += data.form_contents[ index ];
					}
				}
				content += data.form_fields;

			content += "</form>";

			swal2( $.extend( {}, SecuPress.swal2Defaults, SecuPress.swal2ConfirmDefaults, {
				title:             data.form_title,
				html:              content,
				type:              swal2Type,
				confirmButtonText: SecuPressi18nScanner.fixit
			} ) ).then( function ( isConfirm ) {
				var params, $row;

				if ( ! isConfirm ) {
					return;
				}

				swal2.enableLoading();

				params = $( "#form_manual_fix" ).serializeArray();
				$row   = $( "#" + test );

				$.post( ajaxurl, params, null, "json" )
				.done( function( r ) {
					// Display fix result.
					if ( secupressDisplayFixResult( r, test, true ) ) {
						// If we need a manual fix, store the info and re-run.
						if ( secupressManualFixNeeded( r.data ) ) {
							secupressScans.manualFix[ test ] = r.data;
							secupressManualFixit( test );
						}
						// The fix is successfull.
						else {
							// Trigger an event.
							$( "body" ).trigger( "manualFixDone.secupress", [ {
								test: test,
								data: r.data
							} ] );
						}
					} else {
						// Error.
						secupressDisplayFixError( $row, true );
					}
				} )
				.fail( function() {
					// Error.
					secupressDisplayFixError( $row, true );
				} );
			} );
		}


		// What to do when a scan ends.
		$( "body" ).on( "scanDone.secupress", function( e, extra ) {
			/*
			* Available extras:
			* extra.test:   test name.
			* extra.href:   the admin-post.php URL.
			* extra.isBulk: tell if it's a bulk scan.
			* extra.data:   data returned by the ajax call.
			*/
			var $row = $( "#" + extra.test ),
				$fixitWrap, $refixitWrap;

			// If we have delayed fixes, launch the first in queue now.
			if ( secupressScans.delayedFixes.length ) {
				secupressFixFirstQueued( extra.isBulk );
			}

			// If we have a good result, empty the fix cell.
			if ( "good" === extra.data.class ) {
				//secupressSetStatusClass( $row.children( ".secupress-fix-result" ), "cantfix" );
				secupressAddFixStatusText( $row, "" );
				secupressAddFixResult( $row, "" );
			}

			// Add the fix result.
			if ( "" !== extra.data.fix_msg ) {
				secupressAddFixResult( $row, extra.data.fix_msg );
			}

			// Change the scan button text.
			$row.find( ".secupress-scanit .text" ).text( SecuPressi18nScanner.reScan );
		} );


		// What to do after ALL scans end.
		$( "body" ).on( "allScanDone.secupress", function( e, extra ) {
			/*
			* Available extras:
			* extra.isBulk: tell if it's a bulk scan.
			*/
			var $button = $( '.button-secupress-scan' ).last(),
				params;

			// If it's a One-click Scan, keep track of the date.
			if ( secupressIsButtonDisabled( $button ) ) {
				params = {
					"action":   "secupress-update-oneclick-scan-date",
					"_wpnonce": $button.data( "nonce" )
				};

				$.getJSON( ajaxurl, params )
				.done( function( r ) {
					if ( $.isPlainObject( r ) && r.success && r.data ) {
						secupressUpdateDate( r.data );
					}
				} )
				.always( function() {
					secupressEnableButtons( $( '.button-secupress-scan' ) );
					// Get counters and print them in the page.
					secupressPrintScoreFromAjax( extra.isBulk );
				} );
			} else {
				// Get counters and print them in the page.
				secupressPrintScoreFromAjax( extra.isBulk );
			}
		} );


		// What to do when a fix ends.
		$( "body" ).on( "fixDone.secupress", function( e, extra ) {
			/*
			* Available extras:
			* extra.test:      test name.
			* extra.href:      the admin-post.php URL.
			* extra.isBulk:    tell if it's a bulk fix.
			* extra.manualFix: tell if the fix needs a manual fix.
			* extra.data:      data returned by the ajax call.
			*/
			var $row = $( "#" + extra.test ),
				bulk = extra.isBulk ? "bulk" : "";

			// Go for a new scan.
			$row.find( ".secupress-scanit" ).trigger( bulk + "scan.secupress" );

			// Display the "Fix it" or "Retry to fix" button.
			if ( extra.data.class && ! extra.manualFix ) {
				$row.addClass( "has-fix-status" ).removeClass( "no-fix-status" );
			} else {
				$row.addClass( "no-fix-status" ).removeClass( "has-fix-status" );
			}
		} );


		// What to do after ALL fixes end.
		$( "body" ).on( "allFixDone.secupress", function( e, extra ) {
			/*
			* Available extras:
			* extra.isBulk: tell if it's a bulk fix.
			*/
			var $rows        = '',
				manualFixLen = 0,
				oneTest;

			// If some manual fixes need to be done.
			if ( ! $.isEmptyObject( secupressScans.manualFix ) ) {
				// Add a message in each row.
				$.each( secupressScans.manualFix, function( test, data ) {
					if ( secupressScans.manualFix.hasOwnProperty( test ) ) {
						oneTest = test;
						++manualFixLen;
						$rows += ",." + test;
					}
				} );
				$rows = $rows.substr( 1 );
				$rows = $( $rows ).children( ".secupress-scan-result" );
				$rows.children( ".manual-fix-message" ).remove();
				$rows.append( '<div class="manual-fix-message">' + SecuPressi18nScanner.manualFixMsg + "</div>" );

				if ( ! extra.isBulk ) {
					// If it's not a bulk, display the form.
					secupressManualFixit( oneTest );
				} else {
					// Bulk: warn the user that some manual fixes need to be done.
					swal2( $.extend( {}, SecuPress.swal2Defaults, {
						title: 1 === manualFixLen ? SecuPressi18nScanner.oneManualFix : SecuPressi18nScanner.someManualFixes,
					} ) );
				}

				secupressScans.manualFix = {};
			}
		} );


		// What to do after a manual fix.
		$( "body" ).on( "manualFixDone.secupress", function( e, extra ) {
			/*
			* Available extras:
			* extra.test:      test name.
			* extra.data:      data returned by the ajax call.
			*/
			var $row  = $( "#" + extra.test ),
				title = SecuPressi18nScanner.notFixed,
				type  = "error";

			// Go for a new scan.
			$( "#" + extra.test ).find( ".secupress-scanit" ).trigger( "scan.secupress" );

			// Display the "Fix it" or "Retry to fix" button.
			if ( extra.data.class ) {
				$row.addClass( "has-fix-status" ).removeClass( "no-fix-status" );
			} else {
				$row.addClass( "no-fix-status" ).removeClass( "has-fix-status" );
			}

			// Success! (or not)
			if ( "warning" === extra.data.class ) {
				title = SecuPressi18nScanner.fixedPartial;
				type  = "warning";
			} else if ( "good" === extra.data.class ) {
				title = SecuPressi18nScanner.fixed;
				type  = "success";
			}

			swal2( $.extend( {}, SecuPress.swal2Defaults, {
				title: title,
				html:  extra.data.message.replace( /(<ul>|<li>|<\/li><\/ul>)/g, "" ).replace( /<\/li>/g, "<br/><br/>" ),
				type:  type
			} ) );
		} );


		// Show test details.
		$( "body" ).on( "click.secupress keyup", ".secupress-details", function( e ) {
			var test;

			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			test = $( this ).data( "test" );

			swal2( $.extend( {}, SecuPress.swal2Defaults, {
				title: SecuPressi18nScanner.scanDetails,
				html:  $( "#details-" + test ).find( ".details-content" ).html(),
				type:  "info"
			} ) );
		} );


		// Show fix details.
		$( "body" ).on( "click.secupress keyup", ".secupress-details-fix", function( e ) {
			var test;

			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			test = $( this ).data( "test" );

			swal2( $.extend( {}, SecuPress.swal2Defaults, SecuPress.swal2ConfirmDefaults, {
				title:             SecuPressi18nScanner.fixDetails,
				confirmButtonText: SecuPressi18nScanner.fixit,
				reverseButtons:    true,
				html:              $( "#details-fix-" + test ).find( ".details-content" ).html(),
				type:              "info"
			} ) ).then( function ( isConfirm ) {
				if ( isConfirm ) {
					$( "#" + test ).find( ".secupress-fixit" ).trigger( "click.secupress" );
					swal2.close();
				}
			} );
		} );


		// Perform a scan on click ("Scan" button).
		$( "body" ).on( "click.secupress scan.secupress bulkscan.secupress keyup", ".secupress-scanit", function( e ) {
			var $this, href, test, $row, isBulk;

			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			e.preventDefault();

			$this  = $( this );
			href   = $this.attr( "href" );
			test   = secupressGetTestFromUrl( href );
			$row   = $this.closest( ".secupress-item-" + test );
			isBulk = "bulkscan" === e.type;

			secupressScanit( test, $row, href, isBulk );
		} );


		// Perform a scan on click ("One click scan" button).
		$( "body" ).on( "click.secupress bulkscan.secupress keyup", ".button-secupress-scan", function( e ) {
			var $this;

			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			$this = $( this );

			if ( secupressIsButtonDisabled( $this ) ) {
				return;
			}

			e.preventDefault();

			secupressDisableButtons( $( '.button-secupress-scan' ) );
			$( ".secupress-scanit" ).trigger( "bulkscan.secupress" );
			secupressRunProgressBar( $this );
		} );


		// Perform a fix on click ("Fix it" button).
		$( "body" ).on( "click.secupress fix.secupress bulkfix.secupress keyup", ".secupress-fixit", function( e ) {
			var $this, href, test, $row, isBulk;

			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			e.preventDefault();

			$this  = $( this );
			href   = $this.attr( "href" );
			test   = secupressGetTestFromUrl( href );
			$row   = $this.closest( ".secupress-item-" + test );
			isBulk = "bulkfix" === e.type;

			secupressFixit( test, $row, href, isBulk );
		} );


		// Perform a fix on click ("Retry to fix" button).
		$( "body" ).on( "click.secupress keyup", ".secupress-retry-fixit", function( e ) {
			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			e.preventDefault();

			$( this ).closest( ".secupress-item-all" ).find( ".secupress-fixit" ).trigger( "fix.secupress" );
		} );


		// Perform all fixes on click ("One click fix" button).
		$( "body" ).on( "click.secupress bulkfix.secupress keyup", ".button-secupress-fix", function( e ) {
			if ( "keyup" === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			e.preventDefault();

			secupressLaunchSeparatedBulkFix( $( ".secupress-fixit" ) );
			secupressRunProgressBar( $( this ) );
		} );


		// Autoscans.
		$( ".secupress-item-all.autoscan .secupress-scanit" ).trigger( "bulkscan.secupress" );


		// One Click Scan auto.
		if ( SecuPressi18nScanner.firstOneClickScan && secupressScansIsIdle() ) {
			$( ".button-secupress-scan" ).last().trigger( "bulkscan.secupress" );
		}
	} )( window, document, $ );
} );

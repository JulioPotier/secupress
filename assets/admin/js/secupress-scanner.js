/* globals jQuery: false, ajaxurl: false, wp: false, SecuPressi18nScanner: false, SecuPressi18nChart: false, secupressIsSpaceOrEnterKey: false, secupressNotices: false, Chart: false, swal2: false */
// !Global vars ====================================================================================
var SecuPress = {
	swal2Defaults:        {
		confirmButtonText: SecuPressi18nScanner.confirmText,
		cancelButtonText:  SecuPressi18nScanner.cancelText,
		type:              "warning",
		allowOutsideClick: true,
		customClass:       "wpmedia-swal2 secupress-swal2"
	},
	swal2ConfirmDefaults: {
		showCancelButton: true,
		closeOnConfirm:   false
	}
};

SecuPressi18nScanner.step = Number( SecuPressi18nScanner.step );


jQuery( document ).ready( function( $ ) {
	var secupressChart = {},
		secupressChartEls = [];

	if ( document.getElementById( 'status_chart' ) ) {
		secupressChartEls.push( document.getElementById( 'status_chart' ) );
	}

	if ( document.getElementById( 'status_chart_mini' ) ) {
		secupressChartEls.push( document.getElementById( 'status_chart_mini' ) );
	}

	// Get cookie.
	function secupressGetCookie(cname) {
		var name = cname + "=";
		var ca   = document.cookie.split(';');

		for ( var i = 0; i <ca.length; i++ ) {
			var c = ca[i];

			while ( c.charAt(0) === ' ' ) {
				c = c.substring(1);
			}
			if ( c.indexOf( name ) === 0 ) {
				return c.substring( name.length, c.length );
			}
		}
		return '';
	}

	// Tweeter Grade A.
	if ( $( '.secupress-score' ).find( '.letter' ).hasClass( 'lA' ) ) {
		if ( 'ok' !== secupressGetCookie( 'secupresstweeted' ) ) {
			$( '#tweeterA' ).slideDown();
		}
	}

	$('#tweeterA .secupress-button').on( 'click.secupress', function() {
		var now  = new Date(),
			time = now.getTime(),
			expireTime = time + 1000 * 3600 * 24 * 360; // ~= 1 year

		now.setTime( expireTime );
		document.cookie = 'secupresstweeted=ok; expires=' + now.toGMTString() + '; path=/';
	} );

	// a11y function.
	function secupressCouldSay( say ) {
		if ( wp.a11y && wp.a11y.speak && undefined !== say && say ) {
			wp.a11y.speak( say );
		}
	}


	// !Scan Speed. ================================================================
	( function( w, d, $, undefined ) {
		$( '#secupress-button-scan-speed' ).on( 'click', function( e ) {
			$(this).find('span').toggleClass( 'dashicons-arrow-down dashicons-arrow-up' );
			$( '#secupress-scan-speed' ).slideToggle(100);
		} );
		$( 'input[name=secupress-scan-speed]' ).on( 'click', function( e ) {
			var params = {
				"action":   "secupress_set_scan_speed",
				"_wpnonce": $( '#secupress-button-scan-speed' ).data('nonce'),
				"value": $( 'input[name=secupress-scan-speed]:checked' ).val()
			};

			$.getJSON( ajaxurl, params ).done( function(r) {
				SecuPressi18nScanner.offset = r.data.val;
				$( 'input[name=secupress-scan-speed][value='+r.data.text+']' ).prop( 'checked', 'checked' );
				$( '#secupress-button-scan-speed' ).find('span').toggleClass( 'dashicons-arrow-down dashicons-arrow-up' );
				$( '#secupress-scan-speed' ).slideToggle(500);
			} );

		} );
	} )( window, document, $ );

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


	// !"Select all" -------------------------------------------------------------------------------
	(function( w, d, $, undefined ) {

		var jqPropHookChecked = $.propHooks.checked;

		// Force `.prop()` to trigger a `change` event.
		$.propHooks.checked = {
			set: function( elem, value, name ) {
				var ret;

				if ( undefined === jqPropHookChecked ) {
					ret = ( elem[ name ] = value );
				} else {
					ret = jqPropHookChecked( elem, value, name );
				}

				$( elem ).trigger( 'change.secupress' );

				return ret;
			}
		};

		// Check all checkboxes.
		$( '.secupress-sg-content .secupress-row-check' ).on( 'click', function( e ) {
			var $group     = $( this ).closest( '.secupress-scans-group' ),
				allChecked = 0 === $group.find( '.secupress-row-check' ).filter( ':visible:enabled' ).not( ':checked' ).length;

			// Toggle "check all" checkboxes.
			$group.find( '.secupress-toggle-check' ).prop( 'checked', allChecked );
		} )
		// If nothing is checked, change the "Fix all checked issues" button into "Ignore this step".
		.on( 'change.secupress', function( e ) {
			var $this = $( this ),
				$buttons, $checks;

			if ( ! $this.is( ':visible:enabled' ) ) {
				return;
			}

			$buttons = $( '.secupress-button-autofix' );

			// "Ignore this step" => "Fix all checked issues".
			if ( $this.is( ':checked' ) ) {
				// At least one checkbox is checked (this one): display the "Fix all" button.
				if ( $buttons.first().hasClass( 'hidden' ) ) {
					$buttons.next().addClass( 'hidden' );
					$buttons.removeClass( 'hidden' );
				}
				return;
			}

			// "Fix all checked issues" => "Ignore this step".
			$checks = $( '.secupress-sg-content .secupress-row-check' ).filter( ':visible:enabled:checked' );
			// No checkboxes are checked: display the "Ignore" button.
			if ( ! $checks.length && ! $buttons.first().hasClass( 'hidden' ) ) {
				$buttons.addClass( 'hidden' );
				$buttons.next().removeClass( 'hidden' );
			}
		} )
		.first().trigger( 'change.secupress' );

		$( '.secupress-sg-header .secupress-toggle-check' ).on( 'click.wp-toggle-checkboxes', function( e ) {
			var $this          = $( this ),
				$wrap          = $this.closest( '.secupress-scans-group' ),
				controlChecked = $this.prop( 'checked' ),
				toggle         = e.shiftKey || $this.data( 'wp-toggle' );

			$wrap.children( '.secupress-sg-header' ).find( '.secupress-toggle-check' )
				.prop( 'checked', function() {
					var $this = $( this );

					if ( $this.is( ':hidden,:disabled' ) ) {
						return false;
					}

					if ( toggle ) {
						return ! $this.prop( 'checked' );
					}

					return controlChecked;
				} );

			$wrap.children( '.secupress-sg-content' ).find( '.secupress-row-check' )
				.prop( 'checked', function() {
					if ( toggle ) {
						return false;
					}

					return controlChecked;
				} );
		} );

	} )(window, document, $);


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

			if ( SecuPressi18nChart.notscannedyet.value > 0 ) {
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
					percentageInnerCutout: 93,
					tooltipEvents:         [] // remove tooltips
				} );

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

	/**
	 * Disable one or more buttons.
	 * - Add a "aria-disabled" attribute.
	 * - If it's a link: add a "disabled" attribute. If it's a button or input: add a "disabled" attribute.
	 *
	 * @since 1.0
	 *
	 * @param (object) $buttons jQuery object of one or more buttons.
	 *
	 * @return (object) The jQuery object or the buttons.
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

		return $buttons;
	}


	/**
	 * Enable one or more buttons.
	 * - Remove the "aria-disabled" attribute.
	 * - If it's a link: remove the "disabled" attribute. If it's a button or input: remove the "disabled" attribute.
	 *
	 * @since 1.0
	 *
	 * @param (object) $buttons jQuery object of one or more buttons.
	 *
	 * @return (object) The jQuery object or the buttons.
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

		return $buttons;
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


	// Reset the row and the "Fix it" + "Ignore it" buttons (if an error message is displayed, keep it).
	function secupressResetManualFix() {
		var $buttons = $( '.secupress-button-manual-fixit' );
		// Reset the active button icon.
		$buttons.find( '.secupress-icon-shield' ).addClass( 'secupress-icon-check' ).removeClass( 'secupress-icon-shield' );
		// Remove the row class.
		$( '.secupress-mf-content.fixing' ).removeClass( 'fixing' );
		// Activate all buttons.
		$buttons = $buttons.add( '.secupress-button-ignoreit' );
		secupressEnableButtons( $buttons );
	}


	// Print counters in the page.
	function secupressPrintScore( data ) {
		var $filters;

		if ( ! secupressChartEls || ! window.Chart ) {
			return;
		}

		// All various texts.
		$( ".secupress-chart-container .letter" ).replaceWith( data.letter );
		$( ".secupress-score-text" ).html( data.text );
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
	}

	// Some callback that will run after all scans are done and the score has been printed.
	function secupressAllScanDoneCallback( isOneClickScan ) {
		var $row;

		// Step 1: if it's a One-click Scan, reload the page and (maybe) add `&step=1` to the URL.
		if ( 1 === SecuPressi18nScanner.step && isOneClickScan ) {
			// Reload the page and (maybe) add `&step=1`.
			if ( window.location.href.match( /(\?|&)step=1($|&)/ ) ) {
				window.location = window.location.href;
			} else {
				window.location = window.location.href.replace( "&step=0", "" ) + "&step=1";
			}
		}
		// Step 2: when all fixes are done (and the folowing scans), go to step 3.
		else if ( 2 === SecuPressi18nScanner.step ) {
			window.location = window.location.href.replace( /(\?|&)step=2($|&)/, "$1step=3$2" );
		}
		// Step 3: when a manual fix is done (and the folowing scan), or a "manual scan", go to the next manual fix (or to step 4).
		else if ( 3 === SecuPressi18nScanner.step ) {
			$row = $( ".secupress-manual-fix" ).not( ".hide-if-js" );
			$row.find( ".secupress-button-manual-scanit" ).find( ".secupress-icon-shield" ).addClass( "secupress-icon-check" ).removeClass( "secupress-icon-shield" );
			secupressResetManualFix();
			$row.find( ".secupress-button-ignoreit" ).first().trigger( "next.secupress" );
		}
	}


	// Get counters and print them in the page.
	function secupressPrintScoreFromAjax( isBulk, isOneClickScan ) {
		var params;

		if ( typeof isOneClickScan !== "boolean" ) {
			isOneClickScan = false;
		}

		if ( ! SecuPressi18nScanner.i18nNonce ) {
			secupressAllScanDoneCallback( isOneClickScan );
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
		} )
		.always( function() {
			secupressAllScanDoneCallback( isOneClickScan );
		} );
	}


	// If it's not the first scan, draw the charts.
	if ( secupressChartEls && window.Chart ) {
		if ( ! $( '.secupress-scanners-header' ).hasClass( 'secupress-not-scanned-yet' ) ) {
			secupressDrawCharts();
		}
	}


	// !Other UI. ==================================================================================

	// Header tabs specificities.
	( function( w, d, $, undefined ) {

		var $tabs      = $( '.secupress-scan-header-main .secupress-tabs-controls-list a' ),
			$init_tab  = $tabs.filter( '[href="#secupress-scan"]' ),
			$scan_head = $( '.secupress-scanners-header' ),
			$head_item = $( '.secupress-heading' ).find( '.secupress-last-scan-result' ),
			sel_class  = 'secupress-tab-selected';

		// On click on init tab, remove other hidden trigger click.
		$init_tab.on( 'click.secupress', function() {
			$scan_head.removeClass( sel_class );
			$head_item.off( 'click.secupress' );
		} );

		// On click on an other tab.
		$tabs.not( '[href="#secupress-scan"]' ).on( 'click.secupress', function() {
			$scan_head.addClass( sel_class );
			$head_item.on( 'click.secupress', function() {
				$init_tab.trigger( 'click.secupress' );
			} );
		} );

	} )( window, document, $ );


	// !Scans and fixes ============================================================================

	// Get scan button fixed width at first load: this is needed for the progress bar animation.
	( function( w, d, $, undefined ) {

		var $button = $( '.secupress-start-one-click-scan .secupress-button-scan' );
		$button.css( 'width', $button.outerWidth() + 5 );

	} )( window, document, jQuery );


	( function( w, d, $, undefined ) {
		var secupressScans = {
			doingScan:    {},
			doingFix:     {},
			delayedFixes: [],
			total:        0
		};

		// Set the total of available scans...
		function secupressSetScansTotal() {
			var total = $( '#secupress-tests' ).find( '.secupress-item-all' ).length;
			secupressScans.total = total;
		}
		// ...at first page load (at least)
		secupressSetScansTotal();

		// Runs the Progressbar
		function secupressRunProgressBar( $button ) {
			var $sp_1st_scan = $( '.secupress-introduce-first-scan' ),
				$main_header = $( '.secupress-scanners-header' ),
				isFirstScan  = $button.closest( '.secupress-not-scanned-yet' ).length,
				$bar_val     = $( '.secupress-progressbar-val' ),
				$text_val    = $( '.secupress-progress-val-txt' ),
				init_percent = 2,
				secupressProgressTimer;

			$main_header.addClass( 'secupress-scanning' );
			$( '.secupress-scanned-total' ).text( secupressScans.total );

			secupressProgressTimer = setInterval( function() {
				var n_doing = Object.keys( secupressScans.doingScan ).length,
					n_done  = secupressScans.total - n_doing,
					percent = Math.max( n_done / secupressScans.total * 100, init_percent );
				percent = Math.round( Math.min( percent, 100 ) );

				// Progress bar update
				$bar_val.css( 'width', percent + '%' );
				$text_val.text( percent + '\u00A0%' );


				if ( percent >= 100 ) {
					secupressCouldSay( SecuPressi18nScanner.a11y.scanEnded );
					clearInterval( secupressProgressTimer );

					// makes first scan part disappear
					if ( isFirstScan ) {
						$sp_1st_scan.slideUp( 200, function() {

							// hide 4 steps help
							$( '.secupress-open-moreinfo' ).removeClass( 'secupress-activated' );
							$( '#secupress-more-info' ).removeClass( 'secupress-open' ).hide();

							// Show other element (list of scans, tabs, tabs contents).
							$( '.secupress-scan-header-main' ).css('display', 'flex').hide().slideDown( 200, function() {
								$( '.secupress-scanners-header.secupress-not-scanned-yet' ).removeClass( 'secupress-not-scanned-yet' );
							} );

							// draw the chart
							secupressDrawCharts();

						} );
					} else {
						$main_header.removeClass( 'secupress-scanning' );
					}
				}
			}, 100 );
		}


		// Hide step content and run big spinner.
		function secupressRunSpinner() {
			var $to_hide = $( '.secupress-step-content-header, #secupress-tests, .secupress-step-content-footer' ),
				$to_show = $( '#secupress-spinner' );

			// Show/hide items.
			$to_hide.spHide();
			$to_show.spFadeIn().removeClass( 'hidden' );

			// a11y
			secupressCouldSay( SecuPressi18nScanner.a11y.bulkFixStart );
			setTimeout(secupressAllScanDoneCallback, 1000*60*3); // 3 min max
		}


		// Update the date of the last One Click Scan.
		function secupressUpdateDate( data ) {
			var $scoreResultsUl = $( '#secupress-latest' ).find( '.secupress-reports-list' );

			$scoreResultsUl.children( '.secupress-empty' ).remove();

			if ( $scoreResultsUl.children( 'li' ).length === 5 ) {
				$scoreResultsUl.children( 'li:last' ).slideUp( 250, function() {
					$( this ).remove();
					$scoreResultsUl.prepend( data ).find( 'li.hidden' ).slideDown( 250 );
				} );
			} else {
				$scoreResultsUl.prepend( data ).find( 'li.hidden' ).slideDown( 250 );
			}
		}


		// Get test name from an URL.
		function secupressGetTestFromUrl( href ) {
			var test = href.match( /[&?]test=([^&]+)(?:$|&)/ );
			return test ? test[1] : false;
		}


		// Tell if the returned data has required infos.
		function secupressResponseHasRequiredData( r ) {
			// Fail, or there's a problem with the returned data.
			if ( ! r.success || ! $.isPlainObject( r.data ) ) {
				return false;
			}

			// The data is incomplete.
			if ( ! r.data.status || ! r.data.class || ! r.data.message ) {
				return false;
			}

			return true;
		}


		// !Scan (steps 1, 2, and 3). --------------------------------------------------------------

		// Tell there are no scans nor fixes running.
		function secupressScansGlandouillent() {
			return $.isEmptyObject( secupressScans.doingScan ) && $.isEmptyObject( secupressScans.doingFix ) && ! secupressScans.delayedFixes.length;
		}


		// Scan status text.
		function secupressDisplayScanStatusText( $row, statusText ) {
			$row.find( '.secupress-item-status .secupress-label' ).text( statusText );
		}


		// Replace a scan status with an error message.
		function secupressDisplayScanError( $row ) {
			if ( 1 !== SecuPressi18nScanner.step ) {
				return false;
			}

			// Add the status label.
			secupressDisplayScanStatusText( $row, SecuPressi18nScanner.error );

			// Add a "status-error" class to the row.
			$row.addClass( 'status-error' );

			return false;
		}


		// Deal with scan infos.
		function secupressDisplayScanResult( r, $row ) {
			var rowClasses = 'status-error status-good status-bad status-warning status-notscannedyet status-cantfix',
				statusClass;

			// Fail, or there's a problem with the returned data.
			if ( ! secupressResponseHasRequiredData( r ) ) {
				return secupressDisplayScanError( $row );
			}

			// Add the new status as a class.
			statusClass = 'status-' + r.data.class;
			rowClasses  = rowClasses.replace( statusClass, '' ).replace( '  ', ' ' );
			$row.removeClass( rowClasses ).addClass( statusClass );

			if ( 1 === SecuPressi18nScanner.step ) {
				// Add status label.
				secupressDisplayScanStatusText( $row, r.data.status );
				// Add scan results.
				$row.find( '.secupress-item-title' ).html( r.data.message );
			}

			return true;
		}


		var offset = -1;
		// Perform a scan: spinner + row class + ajax call + display result.
		function secupressScanit( test, $row, href, isBulk ) {
			var offsetinit = parseInt( SecuPressi18nScanner.offset );
			if ( -1 === offset ) {
				offset = parseInt( -offsetinit );
			}
			offset = offset + offsetinit;
			if ( ! test ) {
				// Something's wrong here.
				return secupressDisplayScanError( $row );
			}

			if ( secupressScans.doingScan[ test ] ) {
				// Oy! Slow down!
				return;
			}

			// Show our scan is running.
			secupressScans.doingScan[ test ] = 1;
			$row.addClass( 'scanning' ).removeClass( 'status-error' );
			// Ajax call
			setTimeout( function() {
				$.getJSON( href.replace( 'admin-post.php', 'admin-ajax.php' ) )
				.done( function( r ) {
					$( '.secupress-scanned-current' ).html( test.replace(/_/g, ' ') + '<br>' + $('.secupress-item-all').index($row) );
				} )
				.fail( function() {
					// Error
					secupressDisplayScanError( $row );
				} )
				.always( function() {
					delete secupressScans.doingScan[ test ];

					if ( secupressScansGlandouillent() ) {
						$( 'body' ).trigger( 'allScanDone.secupress', [ { isBulk: isBulk } ] );
					}
				} );
			}, offset );
		}


		// !Fix (step 2). --------------------------------------------------------------------------

		// Tell if a test is fixable.
		function secupressIsFixable( $row ) {
			return $row.hasClass( 'status-bad' ) && ! $row.hasClass( 'not-fixable' );
		}


		// Perform a fix: spinner + row class + ajax call + display result.
		function secupressFixit( test, $row, href ) {
			var $button;

			if ( ! test ) {
				// Something's wrong here.
				return;
			}

			if ( secupressScans.doingFix[ test ] ) {
				// Oy! Slow down!
				return;
			}

			if ( ! secupressIsFixable( $row ) ) {
				// Not fixable.
				return;
			}

			// Show our fix is running.
			secupressScans.doingFix[ test ] = 1;
			$row.addClass( 'fixing' ).removeClass( 'status-error' );

			// Ajax call
			$.getJSON( href.replace( 'admin-post.php', 'admin-ajax.php' ) )
			.done( function( r ) {
				delete secupressScans.doingFix[ test ];

				if ( secupressResponseHasRequiredData( r ) ) {
					// Trigger an event on success.
					$( 'body' ).trigger( 'fixDone.secupress', [ {
						test: test,
						href: href,
						data: r.data
					} ] );
				}
			} )
			.fail( function() {
				delete secupressScans.doingFix[ test ];
			} )
			.always( function() {
				if ( $.isEmptyObject( secupressScans.doingFix ) && ! secupressScans.delayedFixes.length ) {
					// No fixes are running and no delayed fixes left in queue. This is the last fix!
					$( 'body' ).trigger( 'allFixDone.secupress' );
				}
			} );
		}


		function secupressFilterNonDelayedButtons( $buttons ) {
			// If we're already performing a fix, do nothing.
			if ( ! $.isEmptyObject( secupressScans.doingFix ) ) {
				return $buttons;
			}
			// Some fixes may need to be queued and delayed.
			$buttons.filter( '.delayed-fix' ).each( function() {
				secupressScans.delayedFixes.push( this );
			} );
			return $buttons.not( '.delayed-fix' );
		}


		function secupressFixFirstQueued() {
			var elem = secupressScans.delayedFixes.shift();
			$( elem ).trigger( 'bulkfix.secupress' );
		}


		function secupressLaunchSeparatedBulkFix() {
			var $buttons = $( '.secupress-sg-content .secupress-row-check' ).filter( ':checked' ).siblings( '.secupress-fixit' );
			$buttons = secupressFilterNonDelayedButtons( $buttons );

			if ( $buttons.length ) {
				// We still have "normal" fixes.
				$buttons.trigger( 'bulkfix.secupress' );
			} else {
				// OK, launch directly the fix of the first item in queue.
				secupressFixFirstQueued();
			}
		}


		// !Manual Fix (step 3). -------------------------------------------------------------------

		// Display an error and reset the row.
		function secupressDisplayManualFixError( $row ) {
			var $notice;

			$row    = $row.addClass( 'status-error' ).find( '.secupress-ic-fix-actions' );
			$notice = $row.next( '.secupress-response-notice' );

			if ( $notice.length ) {
				secupressNotices.remove( $notice );
			}

			$notice = secupressNotices.create( { type: 'bad', message: SecuPressi18nScanner.error } );
			$row.after( $notice );
			secupressCouldSay( SecuPressi18nScanner.error );

			secupressResetManualFix();
			return false;
		}


		// Deal with the manual fix infos: print a message + the form content.
		function secupressDisplayManualFixResult( r, $row ) {
			var $form;

			// Fail, or there's a problem with the returned data.
			if ( ! secupressResponseHasRequiredData( r ) ) {
				return secupressDisplayManualFixError( $row );
			}

			// Add fix results.
			$form = $row.children( 'form.secupress-item-content' );
			r.data.form_contents = r.data.form_contents ? r.data.form_contents : '';

			if ( ! r.data.form_contents ) {
				// Remove the "Fix it" button.
				$form.find( '.secupress-button-manual-fixit' ).remove();
			}

			$form.children( '.secupress-ic-desc' ).html( r.data.message );
			$form.children( '.secupress-ic-fix-actions' ).html( r.data.form_contents );

			return true;
		}


		// Perform a manual fix: launch an ajax call on submit.
		function secupressManualFixit( test ) {
			var $row   = $( '#secupress-mf-content-' + test ),
				params = $row.children( 'form.secupress-item-content' ).serializeArray(),
				$notice;

			if ( ! params ) {
				// Error.
				return secupressDisplayManualFixError( $row );
			}

			$notice = $row.removeClass( 'status-error' ).find( '.secupress-response-notice' );

			if ( $notice.length ) {
				secupressNotices.remove( $notice );
			}

			$row.addClass( 'fixing' ).find( '.secupress-button-manual-fixit .secupress-icon-check' ).addClass( 'secupress-icon-shield' ).removeClass( 'secupress-icon-check' );
			$row.find('button .text').text( SecuPressi18nScanner.fixInProgress );

			$.post( ajaxurl, params, null, 'json' )
			.done( function( r ) {
				// Display fix result.
				if ( secupressDisplayManualFixResult( r, $row ) ) {
					// Trigger an event on success.
					$( 'body' ).trigger( 'manualFixDone.secupress', [ {
						test: test,
						data: r.data
					} ] );
				} else {
					// Error.
					secupressDisplayManualFixError( $row );
				}
			} )
			.fail( function() {
				// Error.
				secupressDisplayManualFixError( $row );
			} );
		}


		// Perform a scan: this one is used in step 3 when the scanner is not fixable with SecuPress (`$fixable = false;`). It is triggered by the "Done" button.
		function secupressManualScanit( test, $row, href ) {
			if ( ! test ) {
				// Something's wrong here.
				return;
			}

			// Show our scan is running.
			$row.addClass( 'scanning' ).find( '.secupress-button-manual-scanit .secupress-icon-check' ).addClass( 'secupress-icon-shield' ).removeClass( 'secupress-icon-check' );

			// Ajax call
			$.getJSON( href.replace( 'admin-post.php', 'admin-ajax.php' ) )
			.done( function( r ) {
				if ( secupressResponseHasRequiredData( r ) ) {
					// Trigger an event on success.
					$( 'body' ).trigger( 'scanDone.secupress', [ {
						test:   test,
						href:   href,
						isBulk: false,
						data:   r.data
					} ] );
				}
			} )
			.always( function() {
				// Show our scan is completed.
				$row.removeClass( 'scanning' );
				$( 'body' ).trigger( 'allScanDone.secupress', [ { isBulk: false } ] );
			} );
		}


		// !Events. ================================================================================

		// !End of scan. ---------------------------------------------------------------------------

		// What to do when a scan ends.
		$( 'body' ).on( 'scanDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.test:   test name.
			* extra.href:   the admin-post.php URL.
			* extra.isBulk: tell if it's a bulk scan.
			* extra.data:   data returned by the ajax call.
			*/
			var $row = $( '#' + extra.test ),
				$fixitWrap, $refixitWrap;

			// If we have delayed fixes (only in bulk), launch the first in queue now.
			if ( secupressScans.delayedFixes.length ) {
				secupressFixFirstQueued();
			}
		} );


		// What to do after ALL scans end.
		$( 'body' ).on( 'allScanDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.isBulk: tell if it's a bulk scan.
			*/
			var $button = $( '.secupress-button-scan' ).last(),
				$row, params;

			// If it's a One-click Scan (step 1), keep track of the date.
			if ( $button.length && secupressIsButtonDisabled( $button ) ) {
				params = {
					'action':   'secupress-update-oneclick-scan-date',
					'_wpnonce': $button.data( 'nonce' )
				};

				$.getJSON( ajaxurl, params )
				.done( function( r ) {
					if ( $.isPlainObject( r ) && r.success && r.data ) {
						secupressUpdateDate( r.data );
					}
				} )
				.always( function() {
					secupressEnableButtons( $( '.secupress-button-scan' ) );
					// Get counters and print them in the page.
					secupressPrintScoreFromAjax( extra.isBulk, true );
				} );
			} else {
				// Get counters and print them in the page.
				secupressPrintScoreFromAjax( extra.isBulk );
			}
			// Don't add stuff here, add it into secupressAllScanDoneCallback().
		} );


		// !End of fix. ----------------------------------------------------------------------------

		// What to do when a fix ends.
		$( 'body' ).on( 'fixDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.test: test name.
			* extra.href: the admin-post.php URL.
			* extra.data: data returned by the ajax call.
			*/
			var $row = $( '#' + extra.test ),
				href = $row.data( 'scan-url' );

			// Go for a new scan.
			secupressScanit( extra.test, $row, href, true );
		} );


		// What to do after ALL fixes end.
		$( 'body' ).on( 'allFixDone.secupress', function( e ) {
			/** Nothing yet. */
		} );


		// !End of manual fix. ---------------------------------------------------------------------

		// What to do after a manual fix.
		$( 'body' ).on( 'manualFixDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.test: test name.
			* extra.data: data returned by the ajax call.
			*/
			var $row = $( '#secupress-mf-content-' + extra.test ),
				href = $row.data( 'scan-url' );

			// Go for a new scan.
			secupressScanit( extra.test, $row, href, false );
		} );


		/** Scan. ------------------------------------------------------------------------------- */

		// Perform a scan on event ("Single scan" button).
		$( 'body' ).on( 'bulkscan.secupress', '.secupress-scanit', function( e ) {
			var $this, href, test, $row;

			e.preventDefault();

			$this = $( this );
			href  = $this.attr( 'href' );
			test  = secupressGetTestFromUrl( href );
			$row  = $this.closest( '.secupress-item-' + test );
			secupressScanit( test, $row, href, true );
		} );


		// Perform a scan on event ("Done" button on step 3).
		$( 'body' ).on( 'click.secupress scan.secupress keyup', '.secupress-button-manual-scanit', function( e ) {
			var $this, href, test, $row;

			if ( 'keyup' === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			$this = $( this );

			if ( secupressIsButtonDisabled( $this ) ) {
				return;
			}

			e.preventDefault();

			href = $this.attr( 'href' );
			test = secupressGetTestFromUrl( href );
			$row = $( '#secupress-mf-content-' + test );

			secupressDisableButtons( $this );
			secupressManualScanit( test, $row, href );
		} );


		// Perform a scan on click ("One click scan" button).
		$( 'body' ).on( 'click.secupress bulkscan.secupress keyup', '.secupress-button-scan', function( e ) {
			var $this;

			if ( 'keyup' === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			// Step 4: go to step 1 and do a One-click Scan.
			if ( 4 === SecuPressi18nScanner.step ) {
				w.location = SecuPressi18nScanner.firstScanURL;
				return false;
			}

			$this = $( this );

			if ( secupressIsButtonDisabled( $this ) ) {
				return;
			}

			e.preventDefault();

			secupressDisableButtons( $( '.secupress-button-scan' ) );
			$( '#secupress-button-scan-speed' ).hide();
			$( '.secupress-scanit' ).trigger( 'bulkscan.secupress' );
			secupressRunProgressBar( $this );
		} );


		/** Fix. -------------------------------------------------------------------------------- */

		// Perform a fix on event ("Single fix" button).
		$( 'body' ).on( 'bulkfix.secupress', '.secupress-fixit', function( e ) {
			var $this, href, test, $row;

			e.preventDefault();

			$this = $( this );
			href  = $this.attr( 'href' );
			test  = secupressGetTestFromUrl( href );
			$row  = $this.closest( '.secupress-item-' + test );

			secupressFixit( test, $row, href );
		} );


		// Perform all selected fixes on click ("One click fix" button).
		$( 'body' ).on( 'click.secupress bulkfix.secupress keyup', '.secupress-button-autofix', function( e ) {
			var $this;

			if ( 'keyup' === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			$this = $( this );

			if ( secupressIsButtonDisabled( $this ) ) {
				return;
			}

			e.preventDefault();

			secupressDisableButtons( $( '.secupress-button-autofix' ) );
			secupressLaunchSeparatedBulkFix();
			secupressRunSpinner();
		} );


		// Perform a manual fix on click ("Fix it" button).
		$( 'body' ).on( 'submit.secupress manualfix.secupress', 'form.secupress-item-content', function( e ) {
			var $form   = $( this ),
				$button = $form.find( '.secupress-button-manual-fixit' ),
				test;

			e.preventDefault();

			if ( secupressIsButtonDisabled( $button ) ) {
				return;
			}

			secupressDisableButtons( $( '.secupress-button-manual-fixit, .secupress-button-ignoreit' ) );

			test = $form.parent( '.secupress-mf-content' ).attr( 'id' ).replace( 'secupress-mf-content-', '' );

			secupressManualFixit( test );
		} );


		// !Various. -------------------------------------------------------------------------------

		// Step 3: hide/show each issue bloc.
		$( 'body' ).on( 'click.secupress next.secupress keyup', '.secupress-button-ignoreit', function( e ) {
			var $this, $parent, $next, item;

			if ( 'keyup' === e.type && ! secupressIsSpaceOrEnterKey( e ) ) {
				return false;
			}

			$this = $( this );

			if ( secupressIsButtonDisabled( $this ) ) {
				return false;
			}

			$parent = $( '.' + $this.attr( 'data-parent' ) );
			$next   = $parent.next();

			// If there is no next bloc.
			if ( ! $next.length ) {
				// Go to step 4.
				w.location = this.href;
				return false;
			}

			// Don't go on step4.
			e.preventDefault();
			// Hide!
			$parent.addClass( 'hide-if-js' );
			// Display the next block and the new advanced text.
			$next.removeClass( 'hide-if-js' );
			// Get the current advanced text and incrment it.
			item = $( '.step3-advanced-text' ).first().text();
			item = Number( item ) + 1;
			$( '.step3-advanced-text' ).text( item );
		} );


		// Autoscans.
		$( '.secupress-item-all.autoscan .secupress-scanit' ).trigger( 'bulkscan.secupress' );


		// One Click Scan auto.
		if ( SecuPressi18nScanner.firstOneClickScan && secupressScansGlandouillent() ) {
			$( '.secupress-button-scan' ).last().trigger( 'bulkscan.secupress' );
		}
	} )( window, document, $ );
} );

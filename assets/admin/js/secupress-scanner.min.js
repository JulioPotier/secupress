jQuery( document ).ready( function( $ ) {

	var secupressChartData = [
		{
			value: SecuPressi18nChart.good.value,
			color:"#88BA0E",
			highlight: "#97cc0f",
			label: SecuPressi18nChart.good.text,
			status: 'good',
		},
		{
			value: SecuPressi18nChart.bad.value,
			color: "#D73838",
			highlight: "#db4848",
			label: SecuPressi18nChart.bad.text,
			status: 'bad',
		},
		{
			value: SecuPressi18nChart.warning.value,
			color: "#FFA500",
			highlight: "#ffad14",
			label: SecuPressi18nChart.warning.text,
			status: 'warning',
		},
		{
			value: SecuPressi18nChart.notscannedyet.value,
			color: "#555",
			highlight: "#5e5e5e",
			label: SecuPressi18nChart.notscannedyet.text,
			status: 'notscannedyet',
		},
	];

	var secupressChartEl = document.getElementById( "status_chart" );
	var secupressChart   = new Chart( secupressChartEl.getContext( "2d" ) ).Doughnut( secupressChartData, {
		animationEasing    : 'easeInOutQuart',
		tooltipEvents      : [],
		showTooltips       : true,
		onAnimationComplete: function() {
			this.showTooltip( [ this.segments[0] ], true );
		}
	} );

	secupressChartEl.onclick = function( e ){
		var activePoints = secupressChart.getSegmentsAtEvent( e );
		$( '.square-filter.statuses button[data-type="' + activePoints[0].status + '"]' ).trigger( "filter.secupress" );
	};

	function secupressPrependDataLi( percent, now ) {
		$( ".score_results ul" ).prepend( '<li class="hidden" data-percent="' + percent + '">' + now + "</li>" ).find( "li.hidden" ).slideDown( 250 );
		$( ".timeago:first" ).timeago();
	}

	function secupressUpdateScore( refresh ) {
		var total                = $( ".status-all" ).length;
		var status_good          = $( ".table-prio-all tr.status-good" ).length;
		var status_warning       = $( ".table-prio-all tr.status-warning" ).length;
		var status_bad           = $( ".table-prio-all tr.status-bad" ).length;
		var status_notscannedyet = $( ".table-prio-all tr.status-notscannedyet" ).length;
		var percent              = Math.floor( status_good * 100 / total );
		var letter               = "&ndash;";
		var d, the_date, dashicon, score_results_ul, replacement, last_percent, now;

		$( ".score_info2 .percent" ).text( "(" + percent + " %)" );

		if ( total != status_notscannedyet ) {
			if ( percent >= 90 ) {
				letter = "A";
			} else if ( percent >= 80 ) {
				letter = "B";
			} else if ( percent >= 70 ) {
				letter = "C";
			} else if ( percent >= 60 ) {
				letter = "D";
			} else if ( percent >= 50 ) {
				letter = "E";
			} else {
				letter = "F";
			}
		}

		if ( "A" === letter ) {
			$( "#tweeterA" ).slideDown();
		} else {
			$( "#tweeterA" ).slideUp();
		}

		$( ".score_info2 .letter" ).html( letter ).removeClass( "lA lB lC lD lE lF" ).addClass( "l" + letter );

		if ( refresh ) {
			d                = new Date();
			the_date         = d.getFullYear() + "-" + ( "0" + ( d.getMonth() + 01 ) ).slice( -2 ) + "-" + ( "0" + d.getDate() ).slice( -2 ) + " " + ( "0" + d.getHours() ).slice( -2 ) + ":" + ( "0" + d.getMinutes() ).slice( -2 );
			dashicon         = '<span class="dashicons mini dashicons-arrow-?-alt2"></span>';
			score_results_ul = $( ".score_results ul" );
			replacement      = "right";
			last_percent     = score_results_ul.find( "li:first" ).data( "percent" );

			if ( last_percent < percent ) {
				replacement = "up";
			} else if ( last_percent > percent ) {
				replacement = "down";
			}

			dashicon = dashicon.replace( "?", replacement );
			now = "<strong>" + dashicon + letter + " (" + percent + ' %)</strong> <span class="timeago" title="' + the_date + '">' + the_date + "</span>";

			if ( score_results_ul.find( "li" ).length === 5 ) {
				score_results_ul.find( "li:last" ).slideUp( 250, function() {
					$( this ).remove();
					secupressPrependDataLi( percent, now );
				} );
			} else {
				secupressPrependDataLi( percent, now );
			}
		}

		secupressChart.segments[0].value = status_good;
		secupressChart.segments[1].value = status_bad;
		secupressChart.segments[2].value = status_warning;
		secupressChart.segments[3].value = status_notscannedyet;
		secupressChart.update();
	}

	secupressUpdateScore();

	jQuery.timeago.settings.strings = jQuery.extend( { numbers: [] }, SecuPressi18nTimeago );

	$( ".timeago" ).timeago();


	// !Filter rows ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	$( "body" ).on( "click filter.secupress", ".square-filter button", function( e ) {
		var $this    = $( this ),
			priority = $this.data( "type" ),
			$tr;

		if ( $this.hasClass( "active" ) ) {
			return;
		}

		$this.addClass( "active" ).siblings().removeClass( "active" );

		if ( $this.parent().hasClass( "statuses" ) ) {

			$( ".status-all" ).addClass( "hidden" );
			$( ".status-" + priority ).removeClass( "hidden" );

		} else if ( $this.parent().hasClass( "priorities" ) ) {

			$( ".table-prio-all" ).addClass( "hidden" );
			$( ".table-prio-" + priority ).removeClass( "hidden" );

		}

		$tr = $( ".table-prio-all table tbody tr.secupress-item-all" ).removeClass( "alternate-1 alternate-2" ).filter( ":visible" );
		$tr.filter( ":odd" ).addClass( "alternate-2" );
		$tr.filter( ":even" ).addClass( "alternate-1" );
	} );


	// !Scans and fixes --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	var doingScan = {}; // Used to tell when all ajax scans are completed (then we can update the graph).
	var doingFix  = {};
	var manualFix = {};
	var secupressDoingFix = false;


	// Update counters of bad results.
	function secupressUpdateBadResultsCounters() {
		var count = $( ".secupress-item-all.status-bad" ).length,
			$counters = $( "#toplevel_page_secupress" ).find( ".update-plugins" );

		$counters.attr( "class", function( i, val ) {
			return val.replace( /^((?:.*\s)?)count-\d+((?:\s.*)?)$/g, "$1count-" + count + "$2" );
		} );

		$counters.children().text( count );
	}


	// Get test name from an URL.
	function secupressGetTestFromUrl( href ) {
		var test = href.match( /[&?]test=([^&]+)(?:$|&)/ );
		return test ? test[1] : false;
	}


	// Tell if a test is fixable.
	function secupressIsFixable( $row ) {
		return $row.hasClass( "status-bad" ) || $row.hasClass( "status-warning" );////
	}


	// Get current scan/fix status.
	function secupressGetCurrentStatus( $el ) {
		var classes, status = false;

		classes = $el.attr( "class" ).replace( /(\s|^)(status-error|status-all)(\s|$)/g, " " ).replace( /^\s+|\s+$/g, "" ).replace( /\s+/, " " ).split( " " );

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
		$row.children( ".secupress-scan-status" ).children( ".secupress-status" ).html( statusText );
	}


	// Add a scan result.
	function secupressAddScanResult( $row, message ) {
		$row.children( ".secupress-scan-result" ).html( message );
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

		// Uncheck the checkbox.
		secupressUncheckTest( $row );

		return false;
	}


	// Fix icon + status text.
	function secupressAddFixStatusText( $row, statusText ) {
		$row.children( ".secupress-fix-status" ).children( ".secupress-status" ).html( statusText );
	}


	// Add a fix result.
	function secupressAddFixResult( $row, message ) {
		$row.children( ".secupress-fix-result" ).html( message );
	}


	// Replace a fix status with an error icon + message.
	function secupressDisplayFixError( $row, warn ) {
		var statusText = '<span class="dashicons dashicons-no secupress-dashicon" aria-hidden="true"></span> ' + SecuPressi18nScanner.error;

		// Add the icon + text.
		secupressAddFixStatusText( $row, statusText );

		// Empty the fix results.
		secupressAddFixResult( $row, "" );

		// Add a "status-error" class to the td.
		$row.children( ".secupress-fix-result" ).addClass( "status-error" );

		// Uncheck the checkbox.
		secupressUncheckTest( $row );

		if ( warn ) {
			secupressErrorWarn();
		}

		return false;
	}


	// Error popup.
	function secupressErrorWarn() {
		swal( {
			title: SecuPressi18nScanner.error,
			type: "error",
			allowOutsideClick: true
		} );
	}


	// Maybe uncheck the test checkbox.
	function secupressUncheckTest( $row ) {
		$row.children( ".secupress-check-column" ).children( ":checked" ).trigger( "click" );
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
		warn = typeof warn === "undefined" ? false : warn;

		// Fail, or there's a problem with the returned data.
		if ( ! r.success || ! $.isPlainObject( r.data ) ) {
			return secupressDisplayFixError( $row, warn );
		}

		// The data is incomplete.
		if ( ! r.data.status || ! r.data.class || ! r.data.message ) {
			return secupressDisplayFixError( $row, warn );
		}

		return true;
	}


	// Deal with scan infos.
	function secupressDisplayScanResult( r, test ) {
		var $row = $( ".secupress-item-" + test ),
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

		// Uncheck the checkbox.
		secupressUncheckTest( $row );

		if ( oldStatus !== r.data.class ) {
			// Tell the row status has been updated.
			$( "body" ).trigger( "testStatusChange.secupress", [ {
				test:      test,
				newStatus: r.data.class,
				oldStatus: oldStatus
			} ] );
		}

		return true;
	}


	// Deal with fix infos.
	function secupressDisplayFixResult( r, test, warn ) {
		var $row = $( ".secupress-item-" + test ),
			$td  = $row.children( ".secupress-fix-result" );

		warn = typeof warn === "undefined" ? false : warn;

		// Fail, or there's a problem with the returned data.
		if ( ! secupressFixResponseHasRequiredData( r, $row, warn ) ) {
			return false;
		}

		// Add the new status as a class.
		secupressSetStatusClass( $td, r.data.class );

		// Add status.
		secupressAddFixStatusText( $row, r.data.status );

		// Add fix results.
		secupressAddFixResult( $row, r.data.message );

		// Uncheck the checkbox.
		secupressUncheckTest( $row );

		return true;
	}


	// Tell if we need a manual fix.
	function secupressManualFixNeeded( data ) {
		return data.form_contents && data.form_fields || data.manualFix;
	}


	// Perform a scan: spinner + row class + ajax call + display result.
	function secupressScanit( test, $row, href, isBulk ) {
		if ( ! test ) {
			// Something's wrong here.
			return secupressDisplayScanError( $row );
		}

		if ( doingScan[ test ] ) {
			// Oy! Slow down!
			return;
		}

		// Show our scan is running.
		doingScan[ test ] = 1;
		$row.addClass( "scanning" ).removeClass( "status-error" );

		// Add the spinner.
		secupressAddScanStatusText( $row, '<img src="' + SecuPressi18nScanner.spinnerUrl + '" alt="" />' );

		// Ajax call
		$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ) )
		.done( function( r ) {
			// Display scan result.
			if ( secupressDisplayScanResult( r, test ) ) {
				delete doingScan[ test ];

				// If it's an auto-scan and the result is good, remove the fix status.
				if ( $row.hasClass( "autoscan" ) ) {
					$row.removeClass( "autoscan" );

					if ( r.data.class === "good" ) {
						$row.children( ".secupress-fix-result" ).html( "" );
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
				delete doingScan[ test ];
			}

		} )
		.fail( function() {
			delete doingScan[ test ];

			// Error
			secupressDisplayScanError( $row );

		} )
		.always( function() {
			// Show our scan is completed.
			$row.removeClass( "scanning" );

			// If this is the last scan in queue, trigger an event.
			if ( $.isEmptyObject( doingScan ) ) {
				$( "body" ).trigger( "allScanDone.secupress", [ { isBulk: isBulk } ] );
			}
		} );
	}


	// Perform a fix: spinner + row class + ajax call + display result + set the var `manualFix` if a manual fix is needed.
	function secupressFixit( test, $row, href, isBulk ) {
		var $button;

		// One fix at a time if no bulk.
		if ( ! isBulk && secupressDoingFix ) {
			return false;
		}
		secupressDoingFix = true;

		if ( ! test ) {
			// Something's wrong here.
			return secupressDisplayFixError( $row, ! isBulk );
		}

		if ( doingFix[ test ] ) {
			// Oy! Slow down!
			return;
		}

		if ( ! secupressIsFixable( $row ) ) {
			secupressUncheckTest( $row );
			return;
		}

		// Show our fix is running.
		doingFix[ test ] = 1;
		$row.addClass( "fixing" ).removeClass( "status-error" );

		// Add the spinner.
		secupressAddFixStatusText( $row, '<img src="' + SecuPressi18nScanner.spinnerUrl + '" alt="" />' );

		// Ajax call
		$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ) )
		.done( function( r ) {
			// Display fix result.
			if ( secupressDisplayFixResult( r, test, ! isBulk ) ) {

				delete doingFix[ test ];

				// If we need a manual fix, store the info.
				if ( secupressManualFixNeeded( r.data ) ) {
					manualFix[ test ] = r.data;
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
				delete doingFix[ test ];
			}

		} )
		.fail( function() {
			delete doingFix[ test ];

			// Error
			secupressDisplayFixError( $row, ! isBulk );

		} )
		.always( function() {
			// Show our fix is completed.
			$row.removeClass( "fixing" );

			// Enable fix buttons again.
			$( ".secupress-fixit" ).removeClass( "disabled" );
			secupressDoingFix = false;

			// If this is the last fix in queue, trigger an event.
			if ( $.isEmptyObject( doingFix ) ) {
				$( "body" ).trigger( "allFixDone.secupress", [ { isBulk: isBulk } ] );
			}
		} );
	}


	// Perform a manual fix: display the form in a popup and launch an ajax call on submit.
	function secupressManualFixit( test ) {
		var content  = "",
			swalType = "info",
			index, data;

		data = manualFix[ test ];
		delete manualFix[ test ];

		data.message = data.message.replace( /(<ul>|<li>|<\/li><\/ul>)/g, "" ).replace( /<\/li>/g, "<br/>" );

		// If the status is "bad" or "warning", `data.message` contains an error message.
		if ( data.class === "bad" || data.class === "warning" ) {
			content += '<div class="sa-error-container show"><div class="icon">!</div><p>' + data.message + '</p></div>';
			swalType = data.class === "bad" ? "error" : "warning";
		}

		content += '<form method="post" id="form_manual_fix" class="secupress-swal-form show-input" action="' + ajaxurl + '">';

			for ( index in data.form_contents ) {
				content += data.form_contents[ index ];
			}
			content += data.form_fields;

		content += "</form>";

		swal( {
				title:               data.form_title,
				text:                content,
				html:                true,
				type:                swalType,
				showLoaderOnConfirm: true,
				closeOnConfirm:      false,
				allowOutsideClick:   true,
				showCancelButton:    true,
				confirmButtonText:   SecuPressi18nScanner.fixit
			},
			function() {
				var params = $( "#form_manual_fix" ).serializeArray(),
					$row   = $( ".secupress-item-" + test );

				$.post( ajaxurl, params )
				.done( function( r ) {
					// Display fix result.
					if ( secupressDisplayFixResult( r, test, true ) ) {

						// If we need a manual fix, store the info and re-run.
						if ( secupressManualFixNeeded( r.data ) ) {
							manualFix[ test ] = r.data;
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

					}
				} )
				.fail( function() {
					// Error
					secupressDisplayFixError( $row, true );
				} );
			}
		);
	}


	// What to do when a scan ends.
	$( "body" ).on( "scanDone.secupress", function( e, extra ) {									console.log("scanDone.secupress: " + extra.test);//console.log(extra);
		/*
		* Available extras:
		* extra.test:   test name.
		* extra.href:   the admin-post.php URL.
		* extra.isBulk: tell if it's a bulk scan.
		* extra.data:   data returned by the ajax call.
		*/
		var $row;

		// If we have a good result, empty the fix cell.
		if ( extra.data.class === "good" ) {
			$row = $( ".secupress-item-" + extra.test );
			secupressSetStatusClass( $row.children( ".secupress-fix-result" ), "cantfix" );
			secupressAddFixStatusText( $row, "" );
			secupressAddFixResult( $row, "" );
		}
	} );


	// What to do after ALL scans end.
	$( "body" ).on( "allScanDone.secupress", function( e, extra ) {									console.log("allScanDone.secupress: " + extra.isBulk);
		/*
		* Available extras:
		* extra.isBulk: tell if it's a bulk scan.
		*/

		// Update the donut only when all scans are done.
		secupressUpdateScore( true );
	} );


	// What to do when a fix ends.
	$( "body" ).on( "fixDone.secupress", function( e, extra ) {										console.log("fixDone.secupress: " + extra.test);//console.log(extra);
		/*
		* Available extras:
		* extra.test:      test name.
		* extra.href:      the admin-post.php URL.
		* extra.isBulk:    tell if it's a bulk fix.
		* extra.manualFix: tell if the fix needs a manual fix.
		* extra.data:      data returned by the ajax call.
		*/

		// Go for a new scan.
		$( ".secupress-item-" + extra.test ).find( ".secupress-scanit" ).trigger( ( extra.isBulk ? "bulk" : "" ) + "scan.secupress" );
	} );


	// What to do after ALL fixes end.
	$( "body" ).on( "allFixDone.secupress", function( e, extra ) {									console.log("allFixDone.secupress: " + extra.isBulk);
		/*
		* Available extras:
		* extra.isBulk: tell if it's a bulk fix.
		*/
		var $rows        = "",
			manualFixLen = 0,
			oneTest;

		// If some manual fixes need to be done.
		if ( ! $.isEmptyObject( manualFix ) ) {
			// Add a message in each row.
			$.each( manualFix, function( test, data ) {
				if ( manualFix.hasOwnProperty( test ) ) {
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
				swal( {
					title: manualFixLen === 1 ? SecuPressi18nScanner.oneManualFix : SecuPressi18nScanner.someManualFixes,
					type: "warning",
					allowOutsideClick: true
				} );
			}

			manualFix = {};

		}

		// Update the donut only when all fixes are done.
		secupressUpdateScore( true );
	} );


	// What to do after a manual fix.
	$( "body" ).on( "manualFixDone.secupress", function( e, extra ) {								console.log("manualFixDone.secupress: " + extra.test);//console.log(extra);
		/*
		* Available extras:
		* extra.test:      test name.
		* extra.data:      data returned by the ajax call.
		*/

		// Go for a new scan.
		$( ".secupress-item-" + extra.test ).find( ".secupress-scanit" ).trigger( "scan.secupress" );

		// Success!
		swal( {
			title: extra.data.class === "warning" ? SecuPressi18nScanner.fixedPartial : SecuPressi18nScanner.fixed,
			text:  extra.data.message.replace( /(<ul>|<li>|<\/li><\/ul>)/g, "" ).replace( /<\/li>/g, "<br/><br/>" ),
			type:  extra.data.class === "warning" ? "warning" : "success",
			allowOutsideClick: true,
			html:  true
		} );
	} );


	// What to do when a status changes.
	$( "body" ).on( "testStatusChange.secupress", function( e, extra ) {							console.log("testStatusChange.secupress: " + extra.test);//console.log(extra);
		/*
		* Available extras:
		* extra.test:      test name.
		* extra.newStatus: the new status.
		* extra.oldStatus: the old status.
		*/

		// Update the counters of bad results.
		secupressUpdateBadResultsCounters();
	} );


	// Show test details.
	$( "body" ).on( "click", ".secupress-details", function( e ) {
		$( this ).closest( ".secupress-item-all" ).next( ".details" ).toggleClass( "hide-if-js" );
	} );


	// Perform a scan on click.
	$( "body" ).on( "click scan.secupress bulkscan.secupress", ".button-secupress-scan, .secupress-scanit", function( e ) {
		var $this = $( this ),
			href, test, $row, isBulk;

		e.preventDefault();

		if ( $this.hasClass( "button-secupress-scan" ) ) {
			// It's the "One Click Scan" button.
			$( ".secupress-scanit" ).trigger( "bulkscan.secupress" );
			return;
		}

		href   = $this.attr( "href" );
		test   = secupressGetTestFromUrl( href );
		$row   = $this.closest( "tr" );
		isBulk = e.type === "bulkscan";

		secupressScanit( test, $row, href, isBulk );
	} );


	// Perform a fix on click.
	$( "body" ).on( "click fix.secupress bulkfix.secupress", ".secupress-fixit", function( e ) {
		$(".secupress-fixit").addClass('disabled');
		var $this = $( this ),
			href, test, $row, isBulk;

		e.preventDefault();

		href   = $this.attr( "href" );
		test   = secupressGetTestFromUrl( href );
		$row   = $this.closest( "tr" );
		isBulk = e.type === "bulkfix";

		secupressFixit( test, $row, href, isBulk );
	} );


	// Autoscans.
	$( ".secupress-item-all.autoscan .secupress-scanit" ).trigger( "bulkscan.secupress" );


	// !Bulk -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	$( "#doaction-high, #doaction-medium, #doaction-low" ).on( "click", function( e ) {
		var $this  = $( this ),
			prio   = $this.attr( "id" ).replace( "doaction-", "" ),
			action = $this.siblings( "select" ).val(),
			$rows  = $this.parents( ".table-prio-all" ).find( "tbody .secupress-check-column :checked" ).parents( ".secupress-item-all" ),
			bulk   = $rows.length < 2 ? "" : "bulk";

		if ( action === "-1" || ! $rows.length ) {
			return;
		}

		$this.siblings( "select" ).val( "-1" );

		switch ( action ) {
			case 'scanit':
				$rows.find( ".secupress-scanit" ).trigger( bulk + "scan.secupress" );
				break;
			case 'fixit':
				$rows.find( ".secupress-fixit" ).trigger( bulk + "fix.secupress" );
				break;
		}
	} );


	// !"Select all" -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	(function( w, d, $, undefined ) {

		var checks, first, last, checked, sliced, lastClicked = {};

		// Check all checkboxes.
		$( "tbody" ).children().children( ".secupress-check-column" ).find( ":checkbox" ).on( "click", function( e ) {
			var prio;

			if ( "undefined" === e.shiftKey ) {
				return true;
			}

			prio = this.className.replace( /^.*secupress-checkbox-([^\s]+)(?:\s.*|$)/g, "$1" );

			if ( e.shiftKey ) {
				if ( ! lastClicked[ prio ] ) {
					return true;
				}
				checks  = $( lastClicked[ prio ] ).closest( ".table-prio-all" ).find( ":checkbox" ).filter( ":visible:enabled" );
				first   = checks.index( lastClicked[ prio ] );
				last    = checks.index( this );
				checked = $( this ).prop( "checked" );

				if ( 0 < first && 0 < last && first !== last ) {
					sliced = ( last > first ) ? checks.slice( first, last ) : checks.slice( last, first );
					sliced.prop( "checked", function() {
						if ( $( this ).closest( "tr" ).is( ":visible" ) ) {
							return checked;
						}

						return false;
					} );
				}
			}

			lastClicked[ prio ] = this;

			// toggle "check all" checkboxes
			var unchecked = $( this ).closest( "tbody" ).find( ":checkbox" ).filter( ":visible:enabled" ).not( ":checked" );
			$( this ).closest( "table" ).children( "thead, tfoot" ).find( ":checkbox" ).prop( "checked", function() {
				return ( 0 === unchecked.length );
			} );

			return true;
		} );

		$( "thead, tfoot" ).find( ".secupress-check-column :checkbox" ).on( "click.wp-toggle-checkboxes", function( e ) {
			var $this          = $(this),
				$table         = $this.closest( "table" ),
				controlChecked = $this.prop( "checked" ),
				toggle         = e.shiftKey || $this.data( "wp-toggle" );

			$table.children( "tbody" ).filter( ":visible" )
				.children().children( ".secupress-check-column" ).find( ":checkbox" )
				.prop( "checked", function() {
					if ( $( this ).is( ":hidden,:disabled" ) ) {
						return false;
					}

					if ( toggle ) {
						return ! $( this ).prop( "checked" );
					}

					return controlChecked ? true : false;
				} );

			$table.children( "thead, tfoot" ).filter( ":visible" )
				.children().children( ".secupress-check-column" ).find( ":checkbox" )
				.prop( "checked", function() {
					if ( toggle ) {
						return false;
					}

					return controlChecked ? true : false;
				} );
		} );

	} )(window, document, $);

} );

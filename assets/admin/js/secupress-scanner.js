jQuery( document ).ready( function( $ ) {

	var spChartData = [
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

	var spChartEl = document.getElementById( "status_chart" );
	var spChart   = new Chart( spChartEl.getContext( "2d" ) ).Doughnut( spChartData, {
		animationEasing    : 'easeInOutQuart',
		tooltipEvents      : [],
		showTooltips       : true,
		onAnimationComplete: function() {
			this.showTooltip( [ this.segments[0] ], true );
		}
	} );

	spChartEl.onclick = function( e ){
		var activePoints = spChart.getSegmentsAtEvent( e );
		$( '.square-filter.statuses button[data-type="' + activePoints[0].status + '"]' ).trigger( "filter.secupress" );
	};

	function prependdatali( percent, now ) {
		$( ".score_results ul" ).prepend( '<li class="hidden" data-percent="' + percent + '">' + now + "</li>" ).find( "li.hidden" ).slideDown( 250 );
		$( ".timeago:first" ).timeago();
	}

	function spUpdateScore( refresh ) {
		var total                = $( ".status-all" ).length;
		var status_good          = $( ".table-prio-all .status-good, .table-prio-all .status-fpositive" ).length;
		var status_warning       = $( ".table-prio-all .status-warning" ).length;
		var status_bad           = $( ".table-prio-all .status-bad" ).length;
		var status_notscannedyet = $( ".table-prio-all .status-notscannedyet" ).length;
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
					prependdatali( percent, now );
				} );
			} else {
				prependdatali( percent, now );
			}
		}

		spChart.segments[0].value = status_good;
		spChart.segments[1].value = status_warning;
		spChart.segments[2].value = status_bad;
		spChart.segments[3].value = status_notscannedyet;
		spChart.update();
	}

	spUpdateScore();

	jQuery.timeago.settings.strings = { //// voir pour mettre celui de WP
		prefixAgo: null,
		prefixFromNow: null,
		suffixAgo: "ago",
		suffixFromNow: null,
		seconds: "a few seconds",
		minute: "1 minute",
		minutes: "%d minutes",
		hour: "1 hour",
		hours: "%d hours",
		day: "1 day",
		days: "%d days",
		month: "1 month",
		months: "%d months",
		year: "1 year",
		years: "%d years",
		wordSeparator: " ",
		numbers: []
	};

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
	var manualFix = [];


	// Update counters of bad results.
	function spUpdateBadResultsCounters() {
		var count = $( ".secupress-item-all.status-bad" ).length,
			$counters = $( "#toplevel_page_secupress" ).find( ".update-plugins" );

		$counters.attr( "class", function( i, val ) {
			return val.replace( /^((?:.*\s)?)count-\d+((?:\s.*)?)$/g, "$1count-" + count + "$2" );
		} );

		$counters.children().text( count );
	}


	// Get test name from an URL.
	function spGetTestFromUrl( href ) {
		var test = href.match( /[&?]test=([^&]+)(?:$|&)/ );
		return test ? test[1] : false;
	}


	// Tell if a test is fixable.
	function spIsFixable( $row ) {
		return $row.hasClass( "status-bad" ) || $row.hasClass( "status-warning" );
	}


	// Badge + status text + show/hide scan buttons.
	function spAddStatusText( $row, statusText ) {
		var $td = $row.children( ".secupress-status" );

		$td.children( ".secupress-row-actions" ).siblings().remove();
		$td.prepend( statusText );
	}


	// Replace a test status with an error icon + message.
	function spDisplayRowError( $row ) {
		var status    = '<span class="dashicons dashicons-no secupress-dashicon" aria-hidden="true"></span> <span class="secupress-status">' + SecuPressi18nScanner.error + "</span>";

		// Add the icon + text.
		spAddStatusText( $row, status );

		// Add a "status-error" class to the row and empty the test results.
		$row.addClass( "status-error" ).children( ".secupress-result" ).html( "" );

		// Uncheck the checkbox.
		sfUncheckTest( $row );

		return false;
	}


	// Maybe uncheck the test checkbox.
	function sfUncheckTest( $row ) {
		$row.children( ".secupress-check-column" ).children( ":checked" ).trigger( "click" );
	}


	// Tell if the returned data (from ajax) has required infos.
	function spResponseHasRequiredData( r, $row ) {
		// Fail, or there's a problem with the returned data.
		if ( ! r.success || ! $.isPlainObject( r.data ) ) {
			return spDisplayRowError( $row );
		}

		// The data is incomplete.
		if ( ! r.data.status || ! r.data.class || ! r.data.message ) {
			return spDisplayRowError( $row );
		}

		return true;
	}


	// Deal with scan infos.
	function spDisplayScanResult( r, test ) {
		var $row = $( ".secupress-item-" + test ),
			classes, oldStatus = null;

		// Fail, or there's a problem with the returned data.
		if ( ! spResponseHasRequiredData( r, $row ) ) {
			return false;
		}

		// Get current status.
		classes = $row.attr( "class" ).replace( /(\s|^)(status-error|status-all)(\s|$)/g, " " ).replace( /^\s+|\s+$/g, "" ).replace( /\s+/, " " ).split( " " );

		$.each( classes, function( i, cl ) {
			if ( 0 === cl.indexOf( "status-" ) ) {
				oldStatus = cl.substr( 7 );
				return false;
			}
		} );

		// Add the new status as a class.
		$row.removeClass( "status-error status-good status-bad status-warning status-notscannedyet" ).addClass( "status-" + r.data.class );

		// Add back the status and the scan button.
		spAddStatusText( $row, r.data.status );

		// Add messages.
		$row.children( ".secupress-result" ).html( r.data.message );

		// A manual fix is needed: add a message.
		if ( r.data.form_contents && r.data.form_fields || r.data.manualFix ) {
			$row.children( ".secupress-result" ).append( '<div class="manual-fix-message">' + SecuPressi18nScanner.manualFixMsg + "</div>" );
		}

		// Uncheck the checkbox.
		sfUncheckTest( $row );

		if ( r.data.class !== oldStatus ) {
			// Tell the row status has been updated.
			$( "body" ).trigger( "testStatusChange.secupress", [ {
				test:      test,
				newStatus: r.data.class,
				oldStatus: oldStatus
			} ] );
		}

		return true;
	}


	// Perform a scan.
	function spScanit( test, $row, href, isBulk ) {
		if ( ! test ) {
			// Something's wrong here.
			return spDisplayRowError( $row );
		}

		if ( doingScan[ test ] ) {
			// Oy! Slow down!
			return;
		}

		// Show our scan is running.
		doingScan[ test ] = 1;
		$row.addClass( "working" ).removeClass( "status-error" );

		// Add the spinner.
		spAddStatusText( $row, '<img src="' + href.replace( "admin-post.php", "images/wpspin_light-2x.gif" ) + '" alt="" />' );

		// Ajax call
		$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ) )
		.done( function( r ) {
			// Display scan result.
			if ( spDisplayScanResult( r, test ) ) {
				delete doingScan[ test ];

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
			spDisplayRowError( $row );

		} )
		.always( function() {
			// Show our scan is completed.
			$row.removeClass( "working" );

			// If this is the last scan in queue, trigger an event.
			if ( $.isEmptyObject( doingScan ) ) {
				$( "body" ).trigger( "allScanDone.secupress", [ { isBulk: isBulk } ] );
			}
		} );
	}


	// Perform a fix.
	function spFixit( test, $row, href, isBulk ) {
		var $button;

		if ( ! test ) {
			// Something's wrong here.
			return spDisplayRowError( $row );
		}

		if ( doingFix[ test ] ) {
			// Oy! Slow down!
			return;
		}

		if ( ! spIsFixable( $row ) ) {
			sfUncheckTest( $row );
			return;
		}

		$button = $row.find( ".fixit" );

		// Show our fix is running.
		doingFix[ test ] = 1;
		$row.addClass( "working" ).removeClass( "status-error" );

		// Add the spinner and hide the button.
		$button.after( '<img src="' + href.replace( "admin-post.php", "images/wpspin_light.gif" ) + '" alt="" />' );

		// Ajax call
		$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ) )
		.done( function( r ) {
			// Display scan result.
			if ( spDisplayScanResult( r, test ) ) {
				delete doingFix[ test ];

				// If it's a bulk action, store the info and bail out.
				if ( isBulk ) {
					manualFix.push( test );
					return;
				}

				// Trigger an event.
				$( "body" ).trigger( "fixDone.secupress", [ {
					test:      test,
					href:      href,
					isBulk:    isBulk,
					manualFix: ( r.data.form_contents && r.data.form_fields ),
					data:      r.data
				} ] );

			} else {
				delete doingFix[ test ];
			}

		} )
		.fail( function() {
			delete doingFix[ test ];

			// Error
			spDisplayRowError( $row );

		} )
		.always( function() {
			// Show the button and remove the spinner.
			$button.next( "img" ).remove();

			// Show our fix is completed.
			$row.removeClass( "working" );

			// If this is the last fix in queue, trigger an event.
			if ( $.isEmptyObject( doingFix ) ) {
				$( "body" ).trigger( "allFixDone.secupress", [ { isBulk: isBulk } ] );
			}
		} );
	}


	// Perform a manual fix.
	function spManualFixit( test, data ) {
		var content, index;

		content = '<form method="post" id="form_manual_fix-' + test + '" action="' + ajaxurl + '">';

		for ( index in data.form_contents ) {
			content += data.form_contents[ index ];
		}
		content += data.form_fields;

		content += "</form>";

		swal( {
				title: data.form_title,
				text: content,
				html: true,
				type: "warning",
				showLoaderOnConfirm: true,
				closeOnConfirm: false,
				allowOutsideClick: true,
				showCancelButton: true,
				confirmButtonText: SecuPressi18nScanner.fixit,
			},
			function() {
				var params = $( "#form_manual_fix-" + test ).serializeArray(),
					$row   = $( ".secupress-item-" + test );

				$.post( ajaxurl, params )
				.done( function( r ) {

					if ( r.success && $.isPlainObject( r.data ) ) {
						r.data.manualFix= ( r.data.class === "bad" );

						// Deal with the scan infos.
						spDisplayScanResult( r, test );

						if ( r.data.class === "warning" ) {
							// Failed.
							swal( {
								title: SecuPressi18nScanner.notFixed,
								type: "error"
							} );
						} else if ( r.data.class === "bad" ) {
							// Success, but it needs another manual fix. Well, it could also mean that the fix failed.
							swal( {
								title: SecuPressi18nScanner.fixedPartial,
								type: "success"
							} );
						} else {
							// Success.
							swal( {
								title: SecuPressi18nScanner.fixed,
								type: "success"
							} );
						}

						// Trigger an event.
						$( "body" ).trigger( "ManualFixDone.secupress", [ {
							test: test,
							manualFix: ( r.data.class === "bad" ),
							data: r.data
						} ] );
					} else {
						spDisplayRowError( $row );

						// Failed.
						swal( {
							title: SecuPressi18nScanner.notFixed,
							type: "error"
						} );
					}
				} )
				.fail( function() {
					// Error
					spDisplayRowError( $row );

					// Failed.
					swal( {
						title: SecuPressi18nScanner.error,
						type: "error"
					} );

				} )
				.always( function() {
					//
				} );
			}
		);
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
	} );


	// What to do after ALL scans end.
	$( "body" ).on( "allScanDone.secupress", function( e, extra ) {
		/*
		* Available extras:
		* extra.isBulk: tell if it's a bulk scan.
		*/

		// Update the donut only when all scans are done.
		spUpdateScore( true );
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

		if ( ! extra.isBulk ) {
			spManualFixit( extra.test, extra.data );
		}
	} );


	// What to do after ALL fixes end.
	$( "body" ).on( "allFixDone.secupress", function( e, extra ) {
		/*
		* Available extras:
		* extra.isBulk: tell if it's a bulk fix.
		*/

		// If some manual fixes need the user to take action.
		if ( manualFix.length ) {
			// Add a message.
			manualFix = "." + manualFix.join( ", ." );
			manualFix = $( manualFix ).children( ".secupress-result" );
			manualFix.children( ".manual-fix-message" ).remove();
			manualFix.append( '<div class="manual-fix-message">' + SecuPressi18nScanner.manualFixMsg + "</div>" );
			manualFix = [];

			// Take that in your face!
			swal( {
				title: manualFix.length === 1 ? SecuPressi18nScanner.oneManualFix : SecuPressi18nScanner.someManualFixes,
				type: "warning"
			} );

		} else {
			// Everything is fine.
			swal( {
				title: SecuPressi18nScanner.allFixed,
				type: "success"
			} );

		}

		// Update the donut only when all fixes are done.
		spUpdateScore( true );
	} );


	// What to do after a manual fix.
	$( "body" ).on( "ManualFixDone.secupress", function( e, extra ) {
		/*
		* Available extras:
		* extra.test:      test name.
		* extra.manualFix: tell if the fix needs a manual fix.
		* extra.data:      data returned by the ajax call.
		*/
	} );


	// What to do when a status changes.
	$( "body" ).on( "testStatusChange.secupress", function( e, extra ) {
		/*
		* Available extras:
		* extra.test:      test name.
		* extra.newStatus: the new status.
		* extra.oldStatus: the old status.
		*/

		// Update the counters of bad results.
		spUpdateBadResultsCounters();
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
			$( ".scanit > .secupress-scanit" ).trigger( "bulkscan.secupress" );
			return;
		}

		href   = $this.attr( "href" );
		test   = spGetTestFromUrl( href );
		$row   = $this.closest( "tr" );
		isBulk = e.type === "bulkscan";

		spScanit( test, $row, href, isBulk );
	} );


	// Perform a fix on click.
	$( "body" ).on( "click fix.secupress bulkfix.secupress", ".secupress-fixit", function( e ) {
		var $this = $( this ),
			href, test, $row, isBulk;

		e.preventDefault();

		href   = $this.attr( "href" );
		test   = spGetTestFromUrl( href );
		$row   = $this.closest( "tr" );
		isBulk = e.type === "bulkfix";

		spFixit( test, $row, href, isBulk );
	} );


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
				$rows.find( ".scanit > .secupress-scanit" ).trigger( bulk + "scan.secupress" );
				break;
			case 'fixit':
				$rows.find( ".secupress-fixit" ).trigger( bulk + "fix.secupress" );
				break;
			case 'fpositive':
				$rows.not( ".status-good, .status-notscannedyet" )
					.addClass( "status-fpositive" )
					.find( ".secupress-dashicon" )
					.removeClass( "dashicons-shield-alt" )
					.addClass( "dashicons-shield" ); //// On ne sauvegarde pas ce statut quelque part ?
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

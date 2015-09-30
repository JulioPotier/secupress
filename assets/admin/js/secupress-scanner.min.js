jQuery( document ).ready( function( $ ) {

	var data = [
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

	var donutId = document.getElementById("status_chart");
	var SecuPressDonutChart = new Chart(donutId.getContext("2d")).Doughnut(data, {
		animationEasing: 'easeInOutQuart',
		onAnimationComplete: function()
		{
			this.showTooltip([this.segments[0]], true);
		},
		tooltipEvents: [],
		showTooltips: true
	});

	donutId.onclick = function(evt){
		var activePoints = SecuPressDonutChart.getSegmentsAtEvent(evt);
		jQuery('.square-filter.statuses button[data-type="'+activePoints[0].status+'"]').click();
	};

	function secupress_maj_score( refresh ) {
		var total = $( '.status-all' ).length;
		var status_good = $( '.status-good, .status-fpositive' ).length;
		var status_warning = $( '.status-warning' ).length;
		var status_bad = $( '.status-bad' ).length;
		var status_notscannedyet = $( '.status-notscannedyet' ).length;
		var percent = Math.floor( status_good * 100 / total );
		var letter = '&ndash;';
		$( '.score_info2 .percent' ).text( '(' + percent + ' %)');
		if ( total != status_notscannedyet ) {
			if ( percent >= 90 ) {
				letter = 'A';
			} else if ( percent >= 80 ) {
				letter = 'B';
			} else if ( percent >= 70 ) {
				letter = 'C';
			} else if ( percent >= 60 ) {
				letter = 'D';
			} else if ( percent >= 50 ) {
				letter = 'E';
			} else {
				letter = 'F';
			}
		}
		if ( 'A' == letter ) {
			$('#tweeterA').slideDown();
		} else {
			$('#tweeterA').slideUp();
		}
		$('.score_info2 .letter').html(letter).removeClass('lA lB lC lD lE lF').addClass('l'+letter);
		if ( refresh ) {
			var d = new Date();
			var the_date = d.getFullYear() + '-' + ("0"+(d.getMonth()+01)).slice(-2) + '-' + ("0" + d.getDate()).slice(-2) + ' ' + ("0"+d.getHours()).slice(-2) + ':' + ("0"+d.getMinutes()).slice(-2);
			var dashicon = '<span class="dashicons mini dashicons-arrow-?-alt2"></span>';
			var score_results_ul = $('.score_results ul');
			var replacement = 'right';
			var last_percent = $( score_results_ul ).find('li:first').data('percent');
			if ( last_percent < percent ) {
				replacement = 'up';
			} else if ( last_percent > percent ) {
				replacement = 'down';
			}
			dashicon = dashicon.replace('?', replacement);
			var now = '<b>' + dashicon + letter + ' (' + percent + ' %)</b> <span class="timeago" title="' + the_date + '">' + the_date + '</span>';
			function prependdatali() {
				$('.score_results ul').prepend('<li class="hidden" data-percent="' + percent + '">' + now + '</li>').find('li.hidden').slideDown('250');
				$('.timeago:first').timeago();
			}
			if ( $(score_results_ul).find('li').length == 5 ) {
				$(score_results_ul).find('li:last').slideUp('250',
					function(){
						$(this).remove();
						prependdatali();
					}
				);
			} else {
				prependdatali();
			}
		}
		SecuPressDonutChart.segments[0].value = status_good;
		SecuPressDonutChart.segments[1].value = status_warning;
		SecuPressDonutChart.segments[2].value = status_bad;
		SecuPressDonutChart.segments[3].value = status_notscannedyet;
		SecuPressDonutChart.update();
	}

	secupress_maj_score();

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

	$('.timeago').timeago();


	// !Filter rows ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

	$( "body" ).on( "click", ".square-filter button", function( e ) {
		var $this    = $( this ),
			priority = $this.data( "type" ),
			$tr;

		e.preventDefault();

		$this.addClass( "active" ).siblings().removeClass( "active" );

		if ( $this.parent().hasClass( "statuses" ) ) {

			$( ".status-all" ).hide();
			$( ".status-" + priority ).show();

		} else if ( $this.parent().hasClass( "priorities" ) ) {

			$( ".table-prio-all" ).hide();
			$( ".table-prio-" + priority ).show();

		}

		$tr = $( ".table-prio-all table tbody tr.secupress-item-all" ).removeClass( "alternate-1 alternate-2" ).filter( ":visible" );
		$tr.filter( ":odd" ).addClass( "alternate-2" );
		$tr.filter( ":even" ).addClass( "alternate-1" );
	} );


	// !Scans and fixes --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	var doingScan = {}; // Used to tell when all ajax scans are completed (then we can update the graph).


	// Update counters of bad results.
	function spUpdateBadsCounters() {
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


	// Badge + status text + show/hide scan buttons.
	function spAddStatusText( $row, status, showActions ) {
		$td = $row.children( ".secupress-status" );

		if ( typeof showActions === "undefined" || showActions ) {
			$td.children( ".secupress-row-actions" ).removeClass( "hidden" ).siblings().remove();
		} else {
			$td.children( ".secupress-row-actions" ).addClass( "hidden" ).siblings().remove();
		}

		$td.prepend( status );
	}


	// Replace a scan status with an error icon + message.
	function spDisplayRowError( $row ) {
		var status = '<span class="dashicons dashicons-no secupress-dashicon" aria-hidden="true"></span> <span class="secupress-status">' + SecuPressi18nScanner.error + "</span>";

		spAddStatusText( $row, status );
		$row.addClass( "status-error" ).children( ".secupress-result" ).html( "" );
	}


	// Tell if the returned data (from ajax) has required infos.
	function spResponseHasRequiredData( r, $row ) {
		// Fail, or there's a problem with the returned data.
		if ( ! r.success || typeof r.data !== "object" ) {
			spDisplayRowError( $row );
			return false;
		}

		// The data is incomplete.
		if ( ! r.data.status || ! r.data.class || ! r.data.message ) {
			spDisplayRowError( $row );
			return false;
		}

		return true;
	}


	// Deal with scan infos.
	function spScanResult( r, test ) {
		var $checkbox = $( "#cb-select-" + test ),
			$row      = $( ".secupress-item-" + test );

		// Fail, or there's a problem with the returned data.
		if ( ! spResponseHasRequiredData( r, $row ) ) {
			return false;
		}

		// Row class.
		$row.removeClass( "status-good status-bad status-warning status-notscannedyet" ).addClass( "status-" + r.data.class );

		// Add back the status and the scan button.
		spAddStatusText( $row, r.data.status );
		$row.children( ".secupress-status" ).find( ".rescanit" ).show().siblings( ".scanit" ).hide();

		// Add messages.
		$row.children( ".secupress-result" ).html( r.data.message );

		// Show/Hide the fix button.
		if ( "good" === r.data.class ) {
			$row.find( ".secupress-row-actions .fixit" ).hide();
		} else {
			$row.find( ".secupress-row-actions .fixit" ).show();
		}

		// Uncheck the checkbox.
		if ( $checkbox.prop( "checked" ) ) {
			$checkbox.trigger( "click" );
		}

		return true;
	}


	// Show test details.
	$( ".secupress-details" ).on( "click", function( e ) {
		e.preventDefault();
		$( "#details-" + $( this ).data( "test" ) ).toggle( 250 );
	} );


	// Perform a scan on click.
	$( "body" ).on( "click scan", ".button-secupress-scan, .secupress-scanit", function( e ) {
		var $this = $( this ),
			href, test, $row;

		e.preventDefault();

		if ( $this.hasClass( "button-secupress-scan" ) ) {
			// It's the "One Click Scan" button.
			$( ".scanit > .secupress-scanit" ).trigger( "scan" );
			return;
		}

		href = $this.attr( "href" );
		test = spGetTestFromUrl( href );
		$row = $this.closest( "tr" ).removeClass( "status-error" );

		if ( ! test ) {
			// Something's wrong here.
			spDisplayRowError( $row );
			return;
		}

		if ( doingScan[ test ] ) {
			// Oy! Slow down!
			return;
		}

		// Spinner
		spAddStatusText( $row, '<img src="' + href.replace( "admin-post.php", "images/wpspin_light-2x.gif" ) + '" alt="" />', false );

		// Tell our ajax call is running.
		$row.addClass( "scanning" );
		doingScan[ test ] = 1;

		// Ajax call
		$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ), function( r ) {

			spScanResult( r, test );

		} ).fail( function() {
			// Error
			spDisplayRowError( $row );

		} ).always( function() {
			// Tell our scan is completed.
			$row.removeClass( "scanning" );
			delete doingScan[ test ];

			// Update the score graph when no scans left.
			if ( $.isEmptyObject( doingScan ) ) {
				secupress_maj_score( true );
			}

			// Update the counters of bad results.
			spUpdateBadsCounters();
		} );
	} );


	// Perform a fix on click.
	$( "body" ).on( "click fix", ".secupress-fixit", function( e ) {
		var $this = $( this ),
			href, test, $row;

		e.preventDefault();

		href = $this.attr( "href" );
		test = spGetTestFromUrl( href );
		$row = $this.closest( "tr" ).removeClass( "status-error" );

		if ( ! test ) {
			// Something's wrong here.
			spDisplayRowError( $row );
			return;
		}

		// Spinner and button.
		$this.hide().after( '<img src="' + href.replace( "admin-post.php", "images/wpspin_light.gif" ) + '" alt="" />' );

		// Show the user we're working.
		$row.addClass( "scanning" );

		// Ajax call
		$.getJSON( href.replace( "admin-post.php", "admin-ajax.php" ), function( r ) {
			var content, index;

			// Deal with the scan infos.
			if ( ! spScanResult( r, test ) ) {
				return;
			}

			// If no need of a manual action, bail out.
			if ( ! r.data.form_contents || ! r.data.form_fields || r.data.class !== "bad" ) {
				////$row.find( ".scanit > .secupress-scanit" ).trigger( "scan" );
				return;
			}

			content = '<form method="post" id="form_manual_fix-' + test + '" action="' + ajaxurl.replace( 'admin-ajax.php', 'admin-post.php' ) + '">';

			for ( index in r.data.form_contents ) {
				content += r.data.form_contents[ index ];
			}

			content += r.data.form_fields;
			content += "</form>";

			swal( {
					title: r.data.form_title,
					text: content,
					html: true,
					type: 'warning',
					showLoaderOnConfirm: true,
					closeOnConfirm: false,
					allowOutsideClick: true,
					showCancelButton: true,
					confirmButtonText: SecuPressi18nScanner.fixit,
				},
				function() {
					var $params = $( "#form_manual_fix-" + test ).serializeArray();

					$.post( ajaxurl, $params, function( r ) {
						if ( r.success ) {
							swal( { title: SecuPressi18nScanner.fixed, type: 'success' } );
						} else {
							swal( { title: SecuPressi18nScanner.notfixed, type: 'error' } );
						}

						// Deal with the scan infos.
						spScanResult( r, test );
					} );
				}
			);
		} )
		.fail( function() {
			// Error
			spDisplayRowError( $row );

		} ).always( function() {
			// Spinner and button
			$this.show().next( "img" ).remove();

			// Chill out
			$row.removeClass( "scanning" );

			// Update the counters of bad results.
			spUpdateBadsCounters();
		} );
	} );


	// !Bulk -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	$( "#doaction-high, #doaction-medium, #doaction-low" ).on( "click", function( e ) {
		var $this  = $( this ),
			prio   = $this.attr( "id" ).replace( "doaction-", "" ),
			action = $this.siblings( "select" ).val(),
			$rows  = $this.parents( ".table-prio-all" ).find( "tbody .secupress-check-column :checked" ).parents( ".secupress-item-all" );

		if ( action === "-1" || ! $rows.length ) {
			return;
		}

		$this.siblings( "select" ).val( "-1" );

		switch ( action ) {
			case 'scanit':
				$rows.find( ".scanit > .secupress-scanit" ).trigger( "scan" );
				break;
			case 'fixit':
				alert('Not yet implemented ;p');
				////$rows.find( ".secupress-fixit" ).trigger( "fix" );
				break;
			case 'fpositive':
				$rows.not( ".status-good, .status-notscannedyet" )
					.addClass( "status-fpositive" )
					.find( ".secupress-dashicon" )
					.removeClass( "dashicons-shield-alt" )
					.addClass( "dashicons-shield" );//// Et c'est tout ? On ne sauvegarde pas ce statut quelque part ?
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

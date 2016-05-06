// Global vars =====================================================================================
var SecuPress = {
	confirmSwalDefaults: {
		confirmButtonText: window.SecuPressi18nScanner.confirmText,
		cancelButtonText:  window.SecuPressi18nScanner.cancelText,
		type:              'warning',
		showCancelButton:  true,
		closeOnConfirm:    false,
		allowOutsideClick: true,
		customClass: 'secupress-swal'
	}
};


jQuery( document ).ready( function( $ ) {

	// !Chart and score ============================================================================
	var secupressChart,
		secupressChartEl = document.getElementById( 'status_chart' ),
		secupressChartData,
		secupressOneClickScanProgress = 0;

	if ( secupressChartEl && window.Chart ) {
		secupressChartData = [
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
			},
			{
				value:     SecuPressi18nChart.notscannedyet.value,
				color:     "#5A626F",
				highlight: "#888888",
				label:     SecuPressi18nChart.notscannedyet.text,
				status:    "notscannedyet",
			},
		];

		secupressChart = new Chart( secupressChartEl.getContext( "2d" ) ).Doughnut( secupressChartData, {
			animationEasing:       'easeInOutQuart',
			showTooltips:          true,
			segmentShowStroke:     false,
			percentageInnerCutout: 90,
			tooltipEvents:         ['mousemove'], // active "hover" effect...
			customTooltips:        function() {} //... but remove tooltips.
		} );

		// Trigger a filter action on Chart Segment click.
		secupressChartEl.onclick = function( e ) {
			var activePoints = secupressChart.getSegmentsAtEvent( e );
			if ( activePoints[0] ) {
				$( '#secupress-type-filters').find('.secupress-big-tab-' + activePoints[0].status ).find('a').trigger( 'click.secupress' );
			}
		};

		// Trigger a filter action on Legend item click.
		$('.secupress-chart-legend').find('li').on('click.secupress', function() {
			$( '#secupress-type-filters').find('.secupress-big-tab-' + $(this).data('status') ).find('a').trigger( 'click.secupress' );
		});
	}


	function secupressUpdateScore( data ) {
		// Only if we're not in a sub-site.
		if ( ! secupressChartEl ) {
			return;
		}

		// All various texts.
		$( ".secupress-chart-container .letter" ).replaceWith( data.letter );
		$( ".secupress-score-text" ).text( data.text );
		$( ".secupress-scan-infos .secupress-score" ).html( data.subtext );
		$( ".secupress-score .percent" ).text( data.percent + "%" );
		$( "#wp-admin-bar-secupress" ).find( ".letter" ).text( data.grade );
		$( "#toplevel_page_" + window.SecuPressi18nScanner.pluginSlug + "_scanners" ).find( ".update-count" ).text( data.bad ).parent().attr( "class", function( i, val ) {
			return val.replace( /count-\d+/, "count-" + data.bad );
		} );

		// Chart.
		secupressChart.segments[0].value = data.good;
		secupressChart.segments[1].value = data.bad;
		secupressChart.segments[2].value = data.warning;
		secupressChart.segments[3].value = data.notscannedyet;
		secupressChart.update();

		// Tabs subtitles.
		$( "#secupress-type-filters" ).find( "a" ).each( function() {
			var $this = $( this ),
				type  = $this.data( "type" );
			$this.children( ".secupress-tab-subtitle" ).text( data[ type + "-text" ] );
		} );

		// Show/Hide the "New" tab.
		if ( ! data.notscannedyet ) {
			$( ".secupress-big-tab-notscannedyet, .secupress-chart-legend .status-notscannedyet" ).remove();
		} else {
			$( ".secupress-count-notscannedyet" ).text( data.notscannedyet );
		}

		// Twitter.
		if ( "A" === data.grade ) {
			$( "#tweeterA" ).slideDown();
		} else {
			$( "#tweeterA" ).slideUp();
		}
	}


	// !Big network: set some data =================================================================
	(function( w, d, $, undefined ) {
		function secupressSetBigData( href, $button, $spinner, $percent ) {
			$.getJSON( href )
			.done( function( r ) {
				if ( ! r.success ) {
					$spinner.replaceWith( '<span class="secupress-error-notif">' + w.SecuPressi18nScanner.error + "</span>" );
					$percent.remove();
					return;
				}
				if ( r.data ) {
					$percent.text( r.data + '%' );

					if ( r.data !== 100 ) {
						// We need more data.
						secupressSetBigData( href, $button, $spinner, $percent );
						return;
					}
				}
				// Finish.
				$button.closest( '.secupress-notice' ).fadeTo( 100 , 0, function() {
					$( this ).slideUp( 100, function() {
						$( this ).remove();
					} );
				} );
			} )
			.fail( function() {
				$spinner.replaceWith( '<span class="secupress-error-notif">' + w.SecuPressi18nScanner.error + "</span>" );
				$percent.remove();
			} );
		}


		$( '.secupress-centralize-blog-options' ).on( 'click', function( e ) {
			var $this    = $( this ),
				href     = $this.attr( "href" ).replace( "admin-post.php", "admin-ajax.php" ),
				$spinner = $( '<img src="' + w.SecuPressi18nScanner.spinnerUrl + '" alt="" class="secupress-spinner" />' ),
				$percent = $( '<span class="secupress-ajax-percent">0%</span>' );

			if ( $this.hasClass( 'running' ) ) {
				return false;
			}
			$this.addClass( 'running' ).parent().append( $spinner ).append( $percent ).find( '.secupress-error-notif' ).remove();

			e.preventDefault();

			secupressSetBigData( href, $this, $spinner, $percent );
		} );
	} )( window, document, $ );


	// !Filter rows (Status bad/good/etc) ==========================================================
	(function( w, d, $, undefined ) {
		$( "#secupress-type-filters" ).find( "a" ).on( "click.secupress", function( e ) {
			var $this    = $( this ),
				priority = $this.data( "type" ),
				current  = "active";

			if ( $this.hasClass( current ) ) {
				return false;
			}

			$this.closest( "ul" ).find( "a" ).removeClass( current );
			$this.addClass( current );

			$( ".status-all" ).addClass( "hidden" ).attr( "aria-hidden", true ).filter( ".status-" + priority ).removeClass( "hidden" ).attr( "aria-hidden", false );
		} ).filter( ".secupress-current" ).trigger( "click.secupress" );
	} )(window, document, $);


	// !Filter Rows (Priority) ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	(function( w, d, $, undefined ) {
		$( '#secupress-priority-filters' ).find('input').on( 'change.secupress', function( e ) {
			var $this		= $( this ),
				priority	= $this.attr( 'name' );

			if ( $this.is(':checked') ) {
				$('.secupress-table-prio-' + priority ).spFadeIn();
			} else {
				$('.secupress-table-prio-' + priority ).spHide();
			}
			return false;
		} );
	} )(window, document, $);


	// !Ask for support button (free) ------------------------------------------------------------------------------------------------------------------------------------------------------------------
	(function( w, d, $, undefined ) {
		$( '.secupress-ask-support-free' ).on( 'click', function( e ) {
			e.preventDefault();

			swal( {
				title:              w.SecuPressi18nScanner.supportTitle,
				confirmButtonText:  w.SecuPressi18nScanner.supportButton,
				showCancelButton:   true,
				html:               w.SecuPressi18nScanner.supportContentFree,
				confirmButtonColor: '#F1C40F',
				type:               "question",
				allowOutsideClick:  true,
				customClass: 'secupress-swal'
			} ).then( function( isConfirm ) {
				if ( true === isConfirm ) {
					swal( {
						title: 'Pro Version needed',
						type:  "error",
						showCancelButton: true,
						confirmButtonText: 'Get Pro now!',
						confirmButtonColor: '#F1C40F',
						reverseButtons: true,
						customClass: 'secupress-swal'
					} );
				}
			} );
		} );
	} )(window, document, $);


	// !Ask for support button (pro) --------------------------------------------------------------------------------------------------------------------------------------------------------------------
	(function( w, d, $, undefined ) {
		$( '.secupress-ask-support-pro' ).on( 'click', function( e ) {
			e.preventDefault();

			swal( {
				title:              w.SecuPressi18nScanner.supportTitle,
				confirmButtonText:  w.SecuPressi18nScanner.supportButton,
				showCancelButton:   true,
				html:               w.SecuPressi18nScanner.supportContentPro,
				type:               "question",
				allowOutsideClick:  true,
				customClass: 'secupress-swal'
			} ).then( function( isConfirm ) {
				if ( true === isConfirm ) {
					swal.enableLoading();
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
	} )(window, document, $);


	// !Scans and fixes ============================================================================
	(function( w, d, $, undefined ) {
		var secupressScans = {
			// Scans.
			doingScan:    {},
			// Fixes.
			doingFix:     {},
			delayedFixes: [],
			// Manual fixes.
			manualFix:    {}
		};

		// Runs the Progressbar, 10 sec min.
		function secupressRunProgressBar() {
			$( ".secupress-progressbar, .secupress-caroupoivre" ).show();
			var secupressProgressTimer = setInterval( function() {
				secupressOneClickScanProgress++;

				if ( secupressOneClickScanProgress >= 65 ) {
					$( ".secupress-caroupoivre #slide2" ).hide();
					$( ".secupress-caroupoivre #slide3" ).show();
				} else if ( secupressOneClickScanProgress >= 35 ) {
					$( ".secupress-caroupoivre #slide1" ).hide();
					$( ".secupress-caroupoivre #slide2" ).show();
				} else if ( secupressOneClickScanProgress >= 0 ) {
					$( ".secupress-caroupoivre #slide1" ).show();
				}

				if ( ! $.isEmptyObject( secupressScans.doingScan ) && secupressOneClickScanProgress > 90 && secupressOneClickScanProgress < 100 ) {
					secupressOneClickScanProgress = 90;
					return;
				}

				secupressOneClickScanProgress = Math.min( secupressOneClickScanProgress, 100 );

				$( ".secupress-progressbar" ).find( "div" ).css( "width", secupressOneClickScanProgress * 5 ).parent().find( "span" ).text( secupressOneClickScanProgress + " %" ); //// *5 = 100 * 5 = 500 (px in my test)

				if ( secupressOneClickScanProgress >= 100 ) {
					$( ".secupress-progressbar, .secupress-caroupoivre, .secupress-caroupoivre #slide3" ).hide( "slow" );
					secupressOneClickScanProgress = 0;
					clearInterval( secupressProgressTimer );
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

			classes = $el.attr( 'class' ).replace( /(\s|^)(status-error|status-all)(\s|$)/g, " " ).replace( /^\s+|\s+$/g, "" ).replace( /\s+/, " " ).split( " " );

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
			$el.removeClass( 'status-error status-good status-bad status-warning status-notscannedyet status-cantfix' ).addClass( 'status-' + status );
		}


		// Scan icon + status text.
		function secupressAddScanStatusText( $row, statusText ) {
			$row.find( '.secupress-status-text' ).html( statusText );
		}


		// Add a scan result.
		function secupressAddScanResult( $row, message ) {
			$row.find( '.secupress-scan-message' ).html( message );
		}


		// Replace a scan status with an error icon + message.
		function secupressDisplayScanError( $row ) {
			var status = '<span class="dashicons dashicons-no secupress-dashicon" aria-hidden="true"></span> ' + w.SecuPressi18nScanner.error;

			// Add the icon + text.
			secupressAddScanStatusText( $row, status );

			// Empty the scan results.
			secupressAddScanResult( $row, "" );

			// Add a "status-error" class to the row.
			$row.addClass( 'status-error' );

			return false;
		}


		// Fix icon + status text.
		function secupressAddFixStatusText( $row, statusText ) {
			$row.find( ".secupress-fix-status-text" ).html( statusText );
		}


		// Add a fix result.
		function secupressAddFixResult( $row, message ) {
			$row.find( ".secupress-fix-result-message" ).html( message );
		}


		// Replace a fix status with an error icon + message.
		function secupressDisplayFixError( $row, warn ) {
			var statusText = '<span class="dashicons dashicons-no secupress-dashicon" aria-hidden="true"></span> ' + w.SecuPressi18nScanner.error;

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


		// Error popup.
		function secupressErrorWarn() {
			swal( {
				title:             w.SecuPressi18nScanner.error,
				confirmButtonText: w.SecuPressi18nScanner.confirmText,
				type:              "error",
				allowOutsideClick: true,
				customClass: 'secupress-swal'
			} );
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
			if ( ! r.data.class || ! r.data.message ) {
				return secupressDisplayFixError( $row, warn );
			}

			return true;
		}


		// Deal with scan infos.
		function secupressDisplayScanResult( r, test ) {
			var $row = $( '#' + test ),
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


		// Deal with fix infos.
		function secupressDisplayFixResult( r, test, warn ) {
			var $row = $( '#' + test ),
				$fix  = $row.find( '.secupress-fix-result' );

			warn = typeof warn === 'undefined' ? false : warn;

			// Fail, or there's a problem with the returned data.
			if ( ! secupressFixResponseHasRequiredData( r, $row, warn ) ) {
				return false;
			}

			// Add the new status as a class.
			secupressSetStatusClass( $fix, r.data.class );

			// Add status.
			secupressAddFixStatusText( $row, r.data.status );

			// Add fix results.
			secupressAddFixResult( $row, r.data.message );

			return true;
		}


		// Tell if we need a manual fix.
		function secupressManualFixNeeded( data ) {
			return data.form_contents && data.form_fields || data.manualFix;
		}


		// Tell there is no scans or fixes running.
		function secupressScansIsIdle() {
			return $.isEmptyObject( secupressScans.doingScan ) && $.isEmptyObject( secupressScans.doingFix ) && ! secupressScans.delayedFixes.length;
		}


		// Update the date of the last One Click Scan.
		function secupressUpdateDate( data ) {
			var $scoreResultsUl = $( "#secupress-latest" ).find( "ul" );

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


		function secupressScanEnd( isBulk ) {
			if ( secupressScansIsIdle() ) {
				$( 'body' ).trigger( 'allScanDone.secupress', [ { isBulk: isBulk } ] );
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

			$( '.secupress-fixit' ).addClass( 'disabled' );

			// Show our fix is running.
			secupressScans.doingFix[ test ] = 1;
			$row.addClass( 'fixing' ).removeClass( 'status-error' );

			// Ajax call
			$.getJSON( href.replace( 'admin-post.php', 'admin-ajax.php' ) )
			.done( function( r ) {
				// Display fix result.
				if ( secupressDisplayFixResult( r, test, ! isBulk ) ) {

					delete secupressScans.doingFix[ test ];

					// If we need a manual fix, store the info.
					if ( secupressManualFixNeeded( r.data ) ) {
						secupressScans.manualFix[ test ] = r.data;
					}

					// Trigger an event.
					$( 'body' ).trigger( 'fixDone.secupress', [ {
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
				$row.removeClass( 'fixing' );

				// Enable fix buttons again.
				if ( ! isBulk ) {
					$( '.secupress-fixit' ).removeClass( 'disabled' );
				}

				secupressFixEnd( isBulk );
			} );
		}


		function secupressFixEnd( isBulk ) {
			if ( $.isEmptyObject( secupressScans.doingFix ) && ! secupressScans.delayedFixes.length ) {
				// No fixes are running and no delayed fixes left in queue. This is the last fix!
				if ( isBulk ) {
					// Enable fix buttons again, only when all fixes are done.
					$( '.secupress-fixit' ).removeClass( 'disabled' );
				}
				// Finally, trigger an event.
				$( 'body' ).trigger( 'allFixDone.secupress', [ { isBulk: isBulk } ] );
			}
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
			$buttons.filter( '.delayed-fix' ).each( function() {
				secupressScans.delayedFixes.push( this );
			} );
			return $buttons.not( '.delayed-fix' );
		}


		function secupressLaunchSeparatedBulkFix( $buttons ) {
			if ( $buttons.length < 2 ) {
				// Not a bulk.
				$buttons.trigger( 'fix.secupress' );
				return;
			}

			$buttons = secupressFilterNonDelayedButtons( $buttons );

			if ( $buttons.length ) {
				// We still have "normal" fixes.
				$buttons.trigger( 'bulkfix.secupress' );
			} else {
				// OK, launch directly the fix of the first item in queue.
				secupressFixFirstQueued( true );
			}
		}


		// Perform a manual fix: display the form in a popup and launch an ajax call on submit.
		function secupressManualFixit( test ) {
			var content  = '',
				swalType = 'info',
				index, data;

			data = secupressScans.manualFix[ test ];
			delete secupressScans.manualFix[ test ];

			data.message = data.message.replace( /(<ul>|<li>|<\/li><\/ul>)/g, '' ).replace( /<\/li>/g, '<br/>' );

			// If the status is "bad" or "warning", `data.message` contains an error message.
			if ( data.class === 'bad' || data.class === 'warning' ) {
				content += '<div class="sa-error-container show"><div class="icon">!</div><p>' + data.message + '</p></div>';
				swalType = data.class === 'bad' ? 'error' : 'warning';
			}

			content += '<form method="post" id="form_manual_fix" class="secupress-swal-form show-input" action="' + ajaxurl + '">';

				for ( index in data.form_contents ) {
					content += data.form_contents[ index ];
				}
				content += data.form_fields;

			content += '</form>';

			swal( $.extend( {}, SecuPress.confirmSwalDefaults, {
				title:             data.form_title,
				html:              content,
				type:              swalType,
				confirmButtonText: w.SecuPressi18nScanner.fixit
			} ) ).then( function ( isConfirm ) {
				var params, $row;

				if ( ! isConfirm ) {
					return;
				}

				swal.enableLoading();

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
		$( 'body' ).on( 'scanDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.test:   test name.
			* extra.href:   the admin-post.php URL.
			* extra.isBulk: tell if it's a bulk scan.
			* extra.data:   data returned by the ajax call.
			*/
			var $row = $( '#' + extra.test );

			// If we have delayed fixes, launch the first in queue now.
			if ( secupressScans.delayedFixes.length ) {
				secupressFixFirstQueued( extra.isBulk );
			}

			// If we have a good result, empty the fix cell.
			if ( "good" === extra.data.class ) {
				secupressSetStatusClass( $row.children( ".secupress-fix-result" ), "cantfix" );
				secupressAddFixStatusText( $row, "" );
				secupressAddFixResult( $row, "" );
			}

			// Add the fix result.
			if ( "" !== extra.data.fix_msg ) {
				secupressAddFixResult( $row, extra.data.fix_msg );
				$row.find( ".secupress-fix-result-retryfix" ).show();
			}

			// Change the scan button text.
			$row.find( ".secupress-scanit .text" ).text( w.SecuPressi18nScanner.reScan );
		} );


		// What to do after ALL scans end.
		$( 'body' ).on( 'allScanDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.isBulk: tell if it's a bulk scan.
			*/
			var $button = $( ".button-secupress-scan" ),
				params;

			// Update counters.
			if ( w.SecuPressi18nScanner.i18nNonce ) {
				params = {
					"action":   "secupress-get-scan-counters",
					"_wpnonce": w.SecuPressi18nScanner.i18nNonce
				};

				$.getJSON( ajaxurl, params )
				.done( function( r ) {
					if ( $.isPlainObject( r ) && r.success && r.data ) {
						secupressUpdateScore( r.data );
					}
				} );
			}

			// If it's a One-click Scan, keep track of the date.
			if ( $button.attr( "disabled" ) ) {
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
					$button.removeAttr( "disabled aria-disabled" );
				} );
			}
		} );


		// What to do when a fix ends.
		$( 'body' ).on( 'fixDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.test:      test name.
			* extra.href:      the admin-post.php URL.
			* extra.isBulk:    tell if it's a bulk fix.
			* extra.manualFix: tell if the fix needs a manual fix.
			* extra.data:      data returned by the ajax call.
			*/
			var bulk = extra.isBulk ? 'bulk' : '';

			// Go for a new scan.
			$( "#" + extra.test ).find( ".secupress-scanit" ).trigger( bulk + "scan.secupress" );
		} );


		// What to do after ALL fixes end.
		$( 'body' ).on( 'allFixDone.secupress', function( e, extra ) {
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
				$rows.append( '<div class="manual-fix-message">' + w.SecuPressi18nScanner.manualFixMsg + "</div>" );

				if ( ! extra.isBulk ) {
					// If it's not a bulk, display the form.
					secupressManualFixit( oneTest );
				} else {
					// Bulk: warn the user that some manual fixes need to be done.
					swal( {
						title: manualFixLen === 1 ? w.SecuPressi18nScanner.oneManualFix : w.SecuPressi18nScanner.someManualFixes,
						type: 'warning',
						allowOutsideClick: true,
						confirmButtonText: w.SecuPressi18nScanner.confirmText,
						customClass: 'secupress-swal'
					} );
				}

				secupressScans.manualFix = {};
			}
		} );


		// What to do after a manual fix.
		$( 'body' ).on( 'manualFixDone.secupress', function( e, extra ) {
			/*
			* Available extras:
			* extra.test:      test name.
			* extra.data:      data returned by the ajax call.
			*/
			var title = w.SecuPressi18nScanner.notFixed,
				type  = "error";

			// Go for a new scan.
			$( "#" + extra.test ).find( ".secupress-scanit" ).trigger( "scan.secupress" );

			// Success! (or not)
			if ( extra.data.class === "warning" ) {
				title = w.SecuPressi18nScanner.fixedPartial;
				type  = "warning";
			} else if ( extra.data.class === "good" ) {
				title = w.SecuPressi18nScanner.fixed;
				type  = "success";
			}

			swal( {
				title: title,
				html: extra.data.message.replace( /(<ul>|<li>|<\/li><\/ul>)/g, "" ).replace( /<\/li>/g, "<br/><br/>" ),
				type: type,
				allowOutsideClick: true,
				confirmButtonText: w.SecuPressi18nScanner.confirmText,
				customClass: 'secupress-swal'
			} );
		} );

		// Show test details.
		$( "body" ).on( "click", ".secupress-details", function( e ) {
			var test = $( this ).data( "test" );
			swal( {
				title: w.SecuPressi18nScanner.scanDetails,
				confirmButtonText: w.SecuPressi18nScanner.confirmText,
				html: $( "#details-" + test ).find( ".details-content" ).html(),
				type: "info",
				allowOutsideClick: true,
				customClass: 'secupress-swal'
			} );
		} );

		// Show fix details.
		$( 'body' ).on( 'click', '.secupress-details-fix', function( e ) {
			var test = $( this ).data( "test" );
			swal( $.extend( {}, SecuPress.confirmSwalDefaults, {
				title: w.SecuPressi18nScanner.fixDetails,
				confirmButtonText: w.SecuPressi18nScanner.fixit,
				html: $( '#details-fix-' + test ).find( '.details-content' ).html(),
				type: 'info',
				closeOnConfirm: true,
				customClass: 'secupress-swal'
			} ) ).then( function ( isConfirm ) {
				if ( isConfirm ) {
					$( '#' + test ).find( '.secupress-fixit' ).trigger( 'click' );
				}
			} );
		} );


		// Perform a scan on click.
		$( "body" ).on( "click scan.secupress bulkscan.secupress", ".button-secupress-scan, .secupress-scanit", function( e ) {
			var $this = $( this ),
				href, test, $row, isBulk;

			e.preventDefault();

			if ( $this.hasClass( "button-secupress-scan" ) ) {
				// It's the "One Click Scan" button.
				$this.attr( { "disabled": "disabled", "aria-disabled": true } );
				$( ".secupress-scanit" ).trigger( "bulkscan.secupress" );
				secupressRunProgressBar();
				return;
			}

			href   = $this.attr( "href" );
			test   = secupressGetTestFromUrl( href );
			$row   = $this.closest( ".secupress-item-" + test );
			isBulk = "bulkscan" === e.type;

			secupressScanit( test, $row, href, isBulk );
		} );


		// Perform a fix on click.
		$( "body" ).on( "click fix.secupress bulkfix.secupress", ".button-secupress-fix, .secupress-fixit", function( e ) {
			var $this = $( this ),
				href, test, $row, isBulk;

			e.preventDefault();

			// It's the "One Click Fix" button.
			if ( $this.hasClass( "button-secupress-fix" ) ) {
				secupressLaunchSeparatedBulkFix( $( ".secupress-fixit" ) );
				return;
			}

			href   = $this.attr( "href" );
			test   = secupressGetTestFromUrl( href );
			$row   = $this.closest( ".secupress-item-" + test );
			isBulk = "bulkfix" === e.type;

			secupressFixit( test, $row, href, isBulk );
		} );


		// Autoscans.
		$( ".secupress-item-all.autoscan .secupress-scanit" ).trigger( "bulkscan.secupress" );


		// One Click Scan auto.
		if ( w.SecuPressi18nScanner.firstOneClickScan && secupressScansIsIdle() ) {
			$( ".button-secupress-scan" ).trigger( "scan.secupress" );
		}
	} )(window, document, $);
} );

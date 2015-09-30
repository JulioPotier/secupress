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
			value: SecuPressi18nChart.warning.value,
			color: "#FFA500",
			highlight: "#ffad14",
			label: SecuPressi18nChart.warning.text,
			status: 'warning',
		},
		{
			value: SecuPressi18nChart.bad.value,
			color: "#D73838",
			highlight: "#db4848",
			label: SecuPressi18nChart.bad.text,
			status: 'bad',
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

	$('body').on( 'click scan','.button-secupress-scan, .secupress-scanit', function( e ) {
		var href, vars, pairs;

		e.preventDefault();

		if ( $( this ).hasClass( 'button-secupress-scan' ) ) {
			$('.secupress-scanit' ).click();
			secupress_maj_score( true );
		}
		else {
			href  = $( this ).attr( 'href' );
			vars  = href.split("?");
			vars  = vars[1].split("&");
			pairs = [];

			for ( var i=0; i<vars.length; i++ ) {
				var temp = vars[i].split("=");
				pairs[ temp[0] ] = temp[1];
			}
			var $saveme = $('.secupress-item-' + pairs['test'] +' .secupress-row-actions:first' ).wrap('<p/>').parent().html();
			$( '.secupress-item-'+pairs.test+' .secupress-status').html('<img src="' + href.replace( 'admin-post.php', 'images/wpspin_light-2x.gif' ) + '" />').parent().css( { backgroundImage: 'repeating-linear-gradient(-45deg, transparent, transparent 10px, rgba(200, 200, 200, 0.1) 10px, rgba(200, 200, 200, 0.1) 20px)' } );

			$.get( href.replace( 'admin-post.php', 'admin-ajax.php' ), function( r ) {
				var $checkbox = $( "#cb-select-" + pairs.test );

				if ( r.success ) {
					if ( r.data[pairs.test].hasOwnProperty('class') ) {
						$('.secupress-item-' + pairs.test )
							.removeClass( 'status-good status-bad status-warning status-notscannedyet' )
							.addClass( 'status-' + r.data[pairs.test].class );
						$('.secupress-item-' + pairs.test +' td.secupress-status span.secupress-dashicon' )
							.removeClass( 'secupress-dashicon-color-good secupress-dashicon-color-bad secupress-dashicon-color-warning secupress-dashicon-color-notscannedyet' )
							.addClass( 'secupress-dashicon-color-' + r.data[pairs.test].class );
					}
					if ( r.data[pairs.test].hasOwnProperty('status') ) {
						$('.secupress-item-' + pairs.test +' td.secupress-status' )
							.html( r.data[pairs['test']].status + $saveme );
					}
					if ( r.data[pairs.test].hasOwnProperty('message') ) {
						$('.secupress-item-' + pairs.test +' td.secupress-result' )
							.html( r.data[pairs.test].message );
					}
					$('.secupress-item-' + pairs.test+' .secupress-status')
						.parent().css( { backgroundImage: 'inherit' } );
					$('.secupress-neverrun, .secupress-neverrun')
						.remove();
					$('.secupress-item-' + pairs.test +' .secupress-row-actions .rescanit').show();
					$('.secupress-item-' + pairs.test +' .secupress-row-actions .scanit').hide();
					if ( 'good' == r.data[pairs.test].class ) {
						$('.secupress-item-' + pairs.test +' .secupress-row-actions .fixit').hide();
					} else {
						$('.secupress-item-' + pairs.test +' .secupress-row-actions .fixit').show();
					}
					if ( ! $( this ).hasClass( 'button-secupress-scan' ) ) {
						secupress_maj_score( true );
					}
				} else {
					console.log( 'AJAX error: ' + pairs.test );
				}

				if ( $checkbox.prop( "checked" ) ) {
					$checkbox.trigger( "click" );
				}

				update_secupress_bads_counters();
			} );
		}
	});


	$('body').on( 'click fix', '.secupress-fixit', function( e ) {
		var href, vars, pairs, t;

		e.preventDefault();

		href  = $( this ).attr( 'href' );
		vars  = href.split("?");
		vars  = vars[1].split("&");
		pairs = [];
		t = this;

		for ( var i=0; i<vars.length; i++ ) {
			var temp = vars[i].split("=");
			pairs[ temp[0] ] = temp[1];
		}

		$( t ).hide();
		$( '.secupress-item-'+pairs.test+' .secupress-status').parent().css( { backgroundImage: 'repeating-linear-gradient(-45deg, transparent, transparent 10px, rgba(200, 200, 200, 0.1) 10px, rgba(200, 200, 200, 0.1) 20px)' } );
		$( t ).after('<img id="load-fix-' + pairs.test + '" src="' + href.replace( 'admin-post.php', 'images/wpspin_light.gif' ) + '" />');

		$.get( href.replace( 'admin-post.php', 'admin-ajax.php' ), function( r ) {
			if ( r.success && r.data.form_contents && r.data.form_fields ) {
				var content = '<form method="post" id="form_manual_fix" action="' + ajaxurl.replace( 'admin-ajax.php', 'admin-post.php' ) + '">';
				for( var index in r.data.form_contents ) { 
					content += r.data.form_contents[ index ];
				}
				content += r.data.form_fields;
				content += '</form>';
				swal({ title: r.data.form_title,
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
						var $params = $('#form_manual_fix').serializeArray();
						$.post( ajaxurl, $params, function( r ) {
							$('.secupress-item-' + pairs.test + ' .secupress-scanit' ).click();
							if ( r.success ) {
								swal({ title: SecuPressi18nScanner.fixed, type: 'success' });
							} else {
								swal({ title: SecuPressi18nScanner.notfixed, type: 'error' });
							}
						} );
					}
			    );
			}
			$('#load-fix-' + pairs.test).remove();
			$( t ).show();
		});
	});

	$('body').on( 'click','.square-filter button', function( e ) {
		e.preventDefault();
		var priority = $(this).data('type');
		$(this).siblings().removeClass('active');
		$(this).addClass('active');
		if ( $(this).parent().hasClass('statuses') ) {
			$('.status-all').hide();
			$('.status-' + priority).show();
		}else
		if ( $(this).parent().hasClass('priorities') ) {
			$('.table-prio-all').hide();
			$('.table-prio-' + priority).show();
		}
		alternate_that();
	});

	function alternate_that() {
		$('.table-prio-all table tbody tr').removeClass('alternate-1 alternate-2');
		$('.table-prio-all table tbody tr.secupress-item-all:visible:odd').addClass('alternate-2');
		$('.table-prio-all table tbody tr.secupress-item-all:visible:even').addClass('alternate-1');
	}

	function update_secupress_bads_counters() {
		var count = $( ".secupress-item-all.status-bad" ).length,
			$counters = $( "#toplevel_page_secupress" ).find( ".update-plugins" );

		$counters.attr( "class", function( i, val ) {
			return val.replace( /^((?:.*\s)?)count-\d+((?:\s.*)?)$/g, "$1count-" + count + "$2" );
		} );

		$counters.children().text( count );
	}

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

	$('.secupress-details').click(function(e){
		e.preventDefault();
		$('#details-'+$(this).data('test')).toggle(250);
	});


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

		switch( action ) {
			case 'scanit':
				$rows.find( ".secupress-scanit" ).trigger( "scan" );
				break;
			case 'fixit':
				alert('Not yet implemented ;p');
				////$rows.find( ".secupress-fixit" ).trigger( "fix" );
				break;
			case 'fpositive':
				$rows.not( ".status-good, .status-notscannedyet" )
					.addClass( "status-fpositive" )
					.find( ".secupress-dashicon" )
					.removeClass( "dashicons-shield-alt secupress-dashicon-color-bad secupress-dashicon-color-warning secupress-dashicon-color-notscannedyet" )
					.addClass( "dashicons-shield secupress-dashicon-color-good" );//// Et c'est tout ? On ne sauvegarde pas ce statut quelque part ?
				break;
		}

		//secupress_maj_score( true );
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


});

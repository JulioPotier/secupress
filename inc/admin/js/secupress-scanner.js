jQuery(document).ready(function($)
{


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

	$('body').on( 'click','.button-secupress-scan, .secupress-scanit', function( e ) {
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
							.html( '<ul class="secupress-result-list">' + r.data[pairs.test].message + '</ul>');
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

				$( "#cb-select-" + pairs.test ).removeProp( "checked" );
			} );
		}
	});


	$('body').on( 'click', '.secupress-fixit', function( e ) {
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
			$('.secupress-item-' + pairs.test + ' .secupress-scanit' ).click();
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

	$('#doaction-high, #doaction-medium, #doaction-low').click(function(e){
		e.preventDefault();
		var prio = $(this).attr('id').replace('doaction-','');
		var action = $('#bulk-action-' + prio).val();
		switch( action ) {
			case 'scanit':
				$('.secupress-checkbox-' + prio + ':checked').parent().parent().find('.secupress-scanit').click();
				break;
			case 'fixit':
				alert('Not yet implemented ;p');
				//$('.secupress-check input:checked').parent().parent().find('.secupress-fixit').click();
				break;
			case 'fpositive':
				$('td.checkbox-' + prio + ' input:checked').parent().parent()
					.filter(':not(.status-good,.status-notscannedyet)')
					.addClass('status-fpositive')
					.find('.secupress-dashicon')
					.removeClass('dashicons-shield-alt secupress-dashicon-color-bad secupress-dashicon-color-warning secupress-dashicon-color-notscannedyet')
					.addClass('dashicons-shield secupress-dashicon-color-good');
				break;
		}
		//secupress_maj_score( true );
	});

	$('input[id^="cb-select-all-"]').click( function(){
		var prio = $(this).attr('id').replace('cb-select-all-', '').replace('2-', '');
		if ( ! $(this).prop('checked') ) {
			$('.secupress-checkbox-'+prio).prop('checked', false);
		} else {
			$('.secupress-checkbox-'+prio).prop('checked', true);
		}
	});

	$('input[class^="secupress-checkbox-"]:not(.me)').click( function(){
		var cssclass = $(this).attr('class');
		var checks = $( '.' + cssclass ).length-2;
		var checkeds = $( '.' + cssclass ).filter(':checked').length;
		var prio = cssclass.replace('secupress-checkbox-', '');
		if ( checks == checkeds ) {
			$('.' + cssclass + '.me').prop('checked', true);
		} else {
			$('.' + cssclass + '.me').prop('checked', false);
		}
	});

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

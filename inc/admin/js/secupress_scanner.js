jQuery(document).ready(function($)
{

	$('body').on( 'click','.button-secupress-scan, .secupress-scanit', function( e ) {
		e.preventDefault();
		if ( $( this ).hasClass( 'button-secupress-scan' ) ) {
			$('.secupress-scanit' ).click();
			secupress_maj_score();
		} else {
			var href = $( this ).attr( 'href' );
			var vars = href.split("?");
			var vars = vars[1].split("&");
			var pairs = new Array();
			for ( var i=0; i<vars.length; i++ ) {
			       var temp = vars[i].split("=");
			       pairs[ temp[0] ] = temp[1];
			}
			$( '.secupress-item-'+pairs['test']+' .secupress-status').html('<img src="' + href.replace( 'admin-post.php', 'images/wpspin_light-2x.gif' ) + '" />').parent().css( { backgroundImage: 'repeating-linear-gradient(-45deg, transparent, transparent 10px, rgba(200, 200, 200, 0.1) 10px, rgba(200, 200, 200, 0.1) 20px)' } );
			$.get( href.replace( 'admin-post.php', 'admin-ajax.php' ), function( r ) {
				if( r.hasOwnProperty('success') && r.success ) {
						if ( r.data[pairs['test']].hasOwnProperty('class') ) {
							$('.secupress-item-' + pairs['test'] )
								.removeClass( 'secupress-status-good secupress-status-bad secupress-status-warning secupress-status-notscannedyet' )
								.addClass( 'secupress-status-' + r.data[pairs['test']].class );
							$('.secupress-item-' + pairs['test'] +' td.secupress-status span.secupress-dashicon' )
								.removeClass( 'secupress-dashicon-color-good secupress-dashicon-color-bad secupress-dashicon-color-warning secupress-dashicon-color-notscannedyet' )
								.addClass( 'secupress-dashicon-color-' + r.data[pairs['test']].class );
						}
						if ( r.data[pairs['test']].hasOwnProperty('status') ) {
							$('.secupress-item-' + pairs['test'] +' td.secupress-status' )
								.html( r.data[pairs['test']].status );
						}
						if ( r.data[pairs['test']].hasOwnProperty('message') ) {
							$('.secupress-item-' + pairs['test'] +' td.secupress-result' )
								.html( '<ul class="secupress-result-list">' + r.data[pairs['test']].message + '</ul>');
						}
						$('.secupress-item-' + pairs['test']+' .secupress-status')
							.parent().css( { backgroundImage: 'inherit' } );
						$('.secupress-neverrun, .secupress-neverrun')
							.remove();
						$('.secupress-item-' + pairs['test'] +' .secupress-row-actions .rescanit').show();
						$('.secupress-item-' + pairs['test'] +' .secupress-row-actions .scanit').hide();
						if ( 'good' == r.data[pairs['test']].class ) {
							$('.secupress-item-' + pairs['test'] +' .secupress-row-actions .fixit').hide();
						} else {
							$('.secupress-item-' + pairs['test'] +' .secupress-row-actions .fixit').show();
						}
						$('#secupress-date').text( '1 min ago' ); ////
						if ( ! $( this ).hasClass( 'button-secupress-scan' ) ) {
							secupress_maj_score();
						}
				} else {
					console.log( 'AJAX error:' + test );
				}
		});
		}
	});

	$('body').on( 'click','.secupress-fixit', function( e ) {
		e.preventDefault();
		alert('Not yet implemented ;p');
	});


	function secupress_maj_score() {
		var percent_item = $( '#secupress-percentage span:first' );
		var total = $( '.status-all' ).length;
		var positives = $( '.status-good, .status-fpositive' ).length;
		var percent = Math.floor( positives * 100 / total );
		console.log( total );
		console.log( positives );
		var text = $( percent_item ).text();
		if ( percent != text ) {
			$( percent_item ).fadeOut(100, function() {
				$( percent_item ).text( percent ).fadeIn(100);
			});
		}
	}

	secupress_maj_score();

	$('.filter-type, .filter-status').click(function(e){
		e.preventDefault();
		var current = $(this).parent().data('who');
		$('.filter-'+current).removeClass('button-primary');
		$(this).addClass('button-primary');
		var current_type = $('.filter-type.button-primary').data('what');
		var current_status = $('.filter-status.button-primary').data('what');
		$.post( window.location, {type: current_type, status: current_status, _spsnonce: $('#_wpnonce').val()} );
		var what = $(this).data('what');
		$('.'+current+'-all').show();
		$('.status-all:not(.status-'+current_status+')').hide();
		$('.type-all:not(.type-'+current_type+')').hide();
	});
	
	$('.filter-type.button-primary, .filter-status.button-primary').click();
	
	$('.secupress-details').click(function(e){
		e.preventDefault();
		$('#details-'+$(this).data('test')).toggle(250);
	});

	$('#filter-submit').click( function(e){
		e.preventDefault();
		var filter = $('#filter-by-status').val();
		$('.status-all').hide();
		$('.status-'+filter).show();
		$('#table-secupress-tests tr').removeClass('alternate');
		$('#table-secupress-tests tr.secupress-item-all:visible:even').addClass('alternate');
	});

	$('#doaction').click(function(e){
		e.preventDefault();
		var action = $('#bulk-action').val();
		switch( action ) {
			case 'scanit':
				$('.secupress-check input:checked').parent().parent().find('.secupress-scanit').click();
			break;
			case 'fixit':
				alert('Not yet implemented ;p');
				//$('.secupress-check input:checked').parent().parent().find('.secupress-fixit').click();
			break;
			case 'fpositive':
				$('td.secupress-check input:checked').parent().parent()
					.filter(':not(.status-good,.status-notscannedyet)')
					.addClass('status-fpositive')
					.find('.secupress-dashicon')
					.removeClass('dashicons-shield-alt secupress-dashicon-color-bad secupress-dashicon-color-warning secupress-dashicon-color-notscannedyet')
					.addClass('dashicons-shield secupress-dashicon-color-good');
				//// do we have to change the label too?
				//$('.secupress-check input:checked').parent().parent()
				//	.find('span.secupress-status')
				//	.text('Good');
			break;
		}
		secupress_maj_score();
	});

	$('#cb-select-all').click( function(e){
		if ( ! $(this).prop('checked') ) {
			$('#table-secupress-tests tbody input[type=checkbox]').prop('checked', false);
		} else {
			$('#table-secupress-tests tbody input[type=checkbox]').prop('checked', true);
		}
	});
	
});
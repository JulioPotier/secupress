jQuery( function($) {

	$('#more-methods').click( function(e) {
		e.preventDefault();
		$(this).slideUp(100);
		$('#more_methods').slideDown('slow');
	});

	$('#http_log_actions').submit( function(e){
		var time = Date.now();
		$('[name$="[since]"]').val( Math.floor( time / 1000 ) );
	});
	var handle = $( ".ui-slider-handle" );

	$( ".secupress-slider" ).slider({
		min: 1,
		max: SecuPressi18nLogs.steps.length - 1,
		// animate: true,
		value: $('#input-' + $(this).data('sync-id') ).val(),
		create: function() {
			handle.html( '<span class="dashicons dashicons-leftright"></span>' );
		},
		slide : function( event, ui ) { secupress_log_slider( this, event, ui ); },
		change: function( event, ui ) { secupress_log_slider( this, event, ui ); },
	});

	function secupress_log_slider( $t, event, ui ) {
		var sync_id = $( $t ).data( 'sync-id' );
		if ( ui.value < $( $t ).data('min') ) {
			$( $t ).slider( 'value', $( $t ).data('min') );
			return false;
		}
		var $slider = $( '[data-sync*="'+sync_id+'"]' );
		$( $t ).parent().find('span:first').text( SecuPressi18nLogs.steps[ ui.value ] );
		if ( ui.value > 1 ) {
			$($slider).slider({ range: 'min' }).data('min', ui.value);
			if ( ui.value >= $($slider).slider( 'value' ) ) {
				$($slider).slider( 'value', ui.value );
			}
			if ($( '[data-sync-id]:last' ).slider( 'value' ) == SecuPressi18nLogs.steps.length - 1 ) {
				$('[name="ignore-param[]"]').prop('disabled', true ).prop('checked', false).parent().css('opacity', '0.5');
			} else {
				$('[name="ignore-param[]"]').prop('disabled', false ).parent().css('opacity', '1');
			}
		} else {
			$($slider).slider({ range: '' }).data('min', 0);
		}
		$('#input-' + sync_id).val( ui.value );
	}

	//// get value by i18n from options
	$($(".secupress-slider").get().reverse()).each( function( i, el ) {
		var v = $('#input-' + $(el).data('sync-id') ).val();
		$(this).slider('value', v);
	});
	$(".secupress-slider").slider({'animate': true});
} );